package main

import (
    "bytes"
    "crypto/rand"
    "database/sql"
    "encoding/base64"
    "encoding/hex"
    "errors"
    "fmt"
    "html/template"
    "image"
    _ "image/gif" // Required for GIF decoding
    "image/jpeg"
    "image/png"
    "io"
    "log"
    "net/http"
    "path/filepath"
    "strconv"
    "strings"
    "sync"
    "time"

    _ "github.com/mattn/go-sqlite3"
    _ "golang.org/x/image/webp"
)

// Image upload configuration
const (
    MaxUploadSize  = 10 << 20 // 10MB
    MaxImageWidth  = 8192
    MaxImageHeight = 8192
)

type Post struct {
	ID      int
	Title   string
	Content string
	Image   string
}

type Reply struct {
	ID          int
	ParentPost  int
	ParentReply sql.NullInt64
	Content     string
	Created     time.Time
	Children    []*Reply // For building the tree
	Depth       int      // For indentation in templates
}

type Image struct {
	ID          int
	Filename    string
	ContentType string
	Data        []byte
	Width       int
	Height      int
	CreatedAt   time.Time
}

var db *sql.DB

var (
	csrfTable = make(map[string]int64)
	csrfTableMutex sync.Mutex
)

func generateRandomToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func getPosts() ([]Post, error) {
    rows, err := db.Query("SELECT id, title, content, COALESCE(image, '') FROM Posts")
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var posts []Post
    for rows.Next() {
        var p Post
        err := rows.Scan(
        	&p.ID,
         	&p.Title,
          	&p.Content,
          	&p.Image,
        )
        if err != nil {
            return nil, err
        }
        posts = append(posts, p)
    }

    return posts, rows.Err()
}

func getPost(id int) (*Post, error) {
    var p Post
    err := db.QueryRow("SELECT id, title, content, COALESCE(image, '') FROM Posts WHERE id = ?", id).Scan(&p.ID, &p.Title, &p.Content, &p.Image)
    if err != nil {
        return nil, err
    }
    return &p, nil
}

// getReply fetches a single reply by ID
func getReply(id int) (*Reply, error) {
	var r Reply
	err := db.QueryRow(`
		SELECT id, parent_post, parent_reply, content, created
		FROM Replies
		WHERE id = ?
	`, id).Scan(&r.ID, &r.ParentPost, &r.ParentReply, &r.Content, &r.Created)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// getRepliesTree fetches all replies for a post and builds them into a tree
func getRepliesTree(postID int) ([]*Reply, error) {
	rows, err := db.Query(`
		SELECT id, parent_post, parent_reply, content, created
		FROM Replies
		WHERE parent_post = ?
		ORDER BY created ASC
	`, postID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// First, collect all replies into a map
	replyMap := make(map[int]*Reply)
	var allReplies []*Reply

	for rows.Next() {
		var r Reply
		err := rows.Scan(
			&r.ID,
			&r.ParentPost,
			&r.ParentReply,
			&r.Content,
			&r.Created,
		)
		if err != nil {
			return nil, err
		}
		r.Children = []*Reply{}
		replyMap[r.ID] = &r
		allReplies = append(allReplies, &r)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	// Build the tree structure
	var rootReplies []*Reply

	for _, reply := range allReplies {
		if reply.ParentReply.Valid {
			// This is a child reply
			parentID := int(reply.ParentReply.Int64)
			if parent, ok := replyMap[parentID]; ok {
				parent.Children = append(parent.Children, reply)
			}
		} else {
			// This is a top-level reply to the post
			rootReplies = append(rootReplies, reply)
		}
	}

	// Set depths for indentation
	setDepths(rootReplies, 0)

	return rootReplies, nil
}

func setDepths(replies []*Reply, depth int) {
	for _, r := range replies {
		r.Depth = depth
		setDepths(r.Children, depth+1)
	}
}

func main() {

	var err error

	// Template functions for post.html
	funcMap := template.FuncMap{
		"multiply": func(a, b int) int {
			return a * b
		},
		"dict": func(values ...any) map[string]any {
			d := make(map[string]any)
			for i := 0; i < len(values); i += 2 {
				key, _ := values[i].(string)
				d[key] = values[i+1]
			}
			return d
		},
	}

	indexTemplate := template.Must(template.ParseFiles(
        "templates/base.html",
        "templates/index.html",
    ))

	createTemplate := template.Must(template.ParseFiles(
        "templates/base.html",
        "templates/create.html",
    ))

	postTemplate := template.Must(template.New("base.html").Funcs(funcMap).ParseFiles(
        "templates/base.html",
        "templates/post.html",
    ))

	replyTemplate := template.Must(template.ParseFiles(
        "templates/base.html",
        "templates/reply.html",
    ))

    db, err = sql.Open("sqlite3", "./posts.db?_foreign_keys=on")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Ensure schema is created
    _, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS Images (
            id           INTEGER   PRIMARY KEY AUTOINCREMENT,
            filename     TEXT      NOT NULL UNIQUE,
            content_type TEXT      NOT NULL,
            data         BLOB      NOT NULL,
            width        INTEGER   NOT NULL,
            height       INTEGER   NOT NULL,
            created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS Posts (
            id      INTEGER   PRIMARY KEY AUTOINCREMENT,
            title   TEXT      NOT NULL,
            content TEXT,
            image   TEXT      REFERENCES Images(filename),
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS Replies (
        	id           INTEGER   PRIMARY KEY AUTOINCREMENT,
         	parent_post  INTEGER   NOT NULL,
          	parent_reply INTEGER,
         	content      TEXT      NOT NULL,
          	created      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          	FOREIGN KEY (parent_post)  REFERENCES Posts(id)   ON DELETE CASCADE,
            FOREIGN KEY (parent_reply) REFERENCES Replies(id) ON DELETE CASCADE
        );
    `)
    if err != nil {
        log.Fatal(err)
    }

    // Add image column if it doesn't exist (for existing databases)
    db.Exec(`ALTER TABLE Posts ADD COLUMN image TEXT`)

    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		posts, err := getPosts()
	    if err != nil {
	        http.Error(w, "Database error", http.StatusInternalServerError)
	        log.Println(err)
	        return
	    }

	    data := map[string]any{
	        "Posts": posts,
	    }

	    indexTemplate.ExecuteTemplate(w, "base", data)
    })

    http.HandleFunc("/create", func(w http.ResponseWriter, r *http.Request) {

    	now := time.Now().Unix()
     	var relative_expire int64 = 300

     	csrfTableMutex.Lock()
		for token, expire := range csrfTable {
			if expire < now {
				delete(csrfTable, token)
			}
		}
		token := generateRandomToken()
      	csrfTable[token] = now + relative_expire
      	csrfTableMutex.Unlock()

    	data := map[string]any{
     		"csrf": token,
     	}

     	createTemplate.ExecuteTemplate(w, "base", data)
    })

    http.HandleFunc("/action-post", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
            return
        }

        // Limit request body size using MaxBytesReader
        r.Body = http.MaxBytesReader(w, r.Body, MaxUploadSize+1024*1024) // Extra 1MB buffer for form overhead

        // Parse the multipart form data
        if err := r.ParseMultipartForm(MaxUploadSize); err != nil {
            if err.Error() == "http: request body too large" {
                http.Error(w, "Request size exceeds maximum allowed size", http.StatusRequestEntityTooLarge)
                return
            }
            http.Error(w, "Bad request", http.StatusBadRequest)
            return
        }

        // Get form values
        csrf := r.FormValue("csrf")
        title := r.FormValue("title")
        content := r.FormValue("content")

        csrfTableMutex.Lock()
        expire, ok := csrfTable[csrf]
        delete(csrfTable, csrf)
        csrfTableMutex.Unlock()

        if !ok || expire < time.Now().Unix() {
            http.Error(w, "Invalid CSRF token", http.StatusBadRequest)
            return
        }

        // Validate
        if title == "" {
            http.Error(w, "Title is required", http.StatusBadRequest)
            return
        }

        // Handle optional image upload with security validation
        var imageName string
        file, header, err := r.FormFile("image")
        if err == nil {
            defer file.Close()

            // Read file data
            data, err := io.ReadAll(file)
            if err != nil {
                http.Error(w, "Failed to read image file", http.StatusInternalServerError)
                return
            }

            // Validate and process the image (security checks + re-encoding)
            filename, contentType, processedData, width, height, err := validateAndProcessImage(data, header.Filename)
            if err != nil {
                var validationErr *ImageValidationError
                if errors.As(err, &validationErr) {
                    http.Error(w, validationErr.Message, http.StatusBadRequest)
                    return
                }
                http.Error(w, "Failed to process image", http.StatusInternalServerError)
                log.Println(err)
                return
            }

            // Save image to database
            if err := saveImage(filename, contentType, processedData, width, height); err != nil {
                http.Error(w, "Failed to save image", http.StatusInternalServerError)
                log.Println(err)
                return
            }

            imageName = filename
        } else if err != http.ErrMissingFile {
            http.Error(w, "Failed to process image upload", http.StatusBadRequest)
            return
        }

        // Insert into database
        _, err = db.Exec(
            "INSERT INTO Posts (title, content, image) VALUES (?, ?, ?)",
            title, content, imageName,
        )
        if err != nil {
            http.Error(w, "Database error", http.StatusInternalServerError)
            log.Println(err)
            return
        }

        // Redirect back to home page
        http.Redirect(w, r, "/", http.StatusSeeOther)
    })

    http.HandleFunc("/action-reply", func(w http.ResponseWriter, r *http.Request) {

    	if r.Method != http.MethodPost {
            http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
            return
        }

        // Parse the form data
        err := r.ParseForm()
        if err != nil {
            http.Error(w, "Bad request", http.StatusBadRequest)
            return
        }
        csrf             := r.FormValue("csrf")
        parentReplyIDStr := r.FormValue("parent_reply")
        content          := r.FormValue("content")

       	csrfTableMutex.Lock()
        expire, ok := csrfTable[csrf]
        delete(csrfTable, csrf)
        csrfTableMutex.Unlock()

        if !ok || expire < time.Now().Unix() {
        	http.Error(w, "Invalid CSRF token", http.StatusBadRequest)
        	return
        }

        // Validate

        parentReplyID, err := strconv.Atoi(parentReplyIDStr)
        if err != nil {
            http.Error(w, "Parent reply ID is required", http.StatusBadRequest)
            return
        }

        // Get the parent reply to infer the post ID
        parentReply, err := getReply(parentReplyID)
        if err == sql.ErrNoRows {
            http.Error(w, "Parent reply not found", http.StatusBadRequest)
            return
        }
        if err != nil {
            http.Error(w, "Database error", http.StatusInternalServerError)
            log.Println(err)
            return
        }

        parentPostID := parentReply.ParentPost

        if content == "" {
            http.Error(w, "Content is required", http.StatusBadRequest)
            return
        }

        // Insert into database
        _, err = db.Exec(
            "INSERT INTO Replies (parent_post, parent_reply, content) VALUES (?, ?, ?)",
            parentPostID, parentReplyID, content,
        )
        if err != nil {
            http.Error(w, "Database error", http.StatusInternalServerError)
            log.Println(err)
            return
        }

        // Redirect back to post page
        http.Redirect(w, r, "/post?id="+strconv.Itoa(parentPostID), http.StatusSeeOther)
    })

    http.HandleFunc("/post", func(w http.ResponseWriter, r *http.Request) {
        idStr := r.URL.Query().Get("id")
        if idStr == "" {
            http.Error(w, "Missing post ID", http.StatusBadRequest)
            return
        }

        id, err := strconv.Atoi(idStr)
        if err != nil {
            http.Error(w, "Invalid post ID", http.StatusBadRequest)
            return
        }

        post, err := getPost(id)
        if err == sql.ErrNoRows {
            http.Error(w, "Post not found", http.StatusNotFound)
            return
        }
        if err != nil {
            http.Error(w, "Database error", http.StatusInternalServerError)
            log.Println(err)
            return
        }

        // Get the reply tree for this post
        replies, err := getRepliesTree(id)
        if err != nil {
            http.Error(w, "Database error", http.StatusInternalServerError)
            log.Println(err)
            return
        }

        // Generate CSRF token for reply form
        now := time.Now().Unix()
        var relative_expire int64 = 300

        csrfTableMutex.Lock()
        for token, expire := range csrfTable {
            if expire < now {
                delete(csrfTable, token)
            }
        }
        token := generateRandomToken()
        csrfTable[token] = now + relative_expire
        csrfTableMutex.Unlock()

        data := map[string]any{
            "Post":    post,
            "Replies": replies,
            "csrf":    token,
        }

        postTemplate.ExecuteTemplate(w, "base", data)
    })

    http.HandleFunc("/reply", func(w http.ResponseWriter, r *http.Request) {
        idStr := r.URL.Query().Get("id")
        if idStr == "" {
            http.Error(w, "Missing reply ID", http.StatusBadRequest)
            return
        }

        id, err := strconv.Atoi(idStr)
        if err != nil {
            http.Error(w, "Invalid reply ID", http.StatusBadRequest)
            return
        }

        reply, err := getReply(id)
        if err == sql.ErrNoRows {
            http.Error(w, "Reply not found", http.StatusNotFound)
            return
        }
        if err != nil {
            http.Error(w, "Database error", http.StatusInternalServerError)
            log.Println(err)
            return
        }

        // Generate CSRF token for reply form
        now := time.Now().Unix()
        var relative_expire int64 = 300

        csrfTableMutex.Lock()
        for token, expire := range csrfTable {
            if expire < now {
                delete(csrfTable, token)
            }
        }
        token := generateRandomToken()
        csrfTable[token] = now + relative_expire
        csrfTableMutex.Unlock()

        data := map[string]any{
            "Reply":  reply,
            "PostID": reply.ParentPost,
            "csrf":   token,
        }

        replyTemplate.ExecuteTemplate(w, "base", data)
    })

    // Serve images from database
    http.HandleFunc("/images/", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet {
            http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
            return
        }

        // Extract filename from path
        filename := strings.TrimPrefix(r.URL.Path, "/images/")
        if filename == "" {
            http.Error(w, "Image not found", http.StatusNotFound)
            return
        }

        // Retrieve image from database
        img, err := getImage(filename)
        if err == sql.ErrNoRows {
            http.Error(w, "Image not found", http.StatusNotFound)
            return
        }
        if err != nil {
            http.Error(w, "Database error", http.StatusInternalServerError)
            log.Println(err)
            return
        }

        // Set appropriate headers
        w.Header().Set("Content-Type", img.ContentType)
        w.Header().Set("Content-Length", strconv.Itoa(len(img.Data)))
        w.Header().Set("Cache-Control", "public, max-age=31536000") // Cache for 1 year
        w.Write(img.Data)
    })

    log.Fatal(http.ListenAndServe(":8080", nil))
}

// Allowed image extensions
var allowedExtensions = map[string]bool{
    ".jpg":  true,
    ".jpeg": true,
    ".png":  true,
    ".gif":  true,
    ".webp": true,
}

// Magic bytes for image format verification
var magicBytes = map[string][]byte{
    ".jpg":  {0xFF, 0xD8, 0xFF},
    ".jpeg": {0xFF, 0xD8, 0xFF},
    ".png":  {0x89, 0x50, 0x4E, 0x47},
    ".gif":  {0x47, 0x49, 0x46, 0x38},
    ".webp": {0x52, 0x49, 0x46, 0x46}, // RIFF header, need to also check for WEBP at bytes 8-11
}

// ImageValidationError provides detailed error messages for validation failures
type ImageValidationError struct {
    Message string
}

func (e *ImageValidationError) Error() string {
    return e.Message
}

// validateAndProcessImage validates and sanitizes an uploaded image.
// It returns the generated filename, content type, sanitized image data, width, height, or an error.
func validateAndProcessImage(data []byte, originalFilename string) (filename string, contentType string, processedData []byte, width int, height int, err error) {
    // Check file size
    if len(data) > MaxUploadSize {
        return "", "", nil, 0, 0, &ImageValidationError{Message: fmt.Sprintf("File size exceeds maximum allowed size of %d bytes", MaxUploadSize)}
    }

    // Get and validate extension
    ext := strings.ToLower(filepath.Ext(originalFilename))
    if ext == "" {
        return "", "", nil, 0, 0, &ImageValidationError{Message: "File has no extension"}
    }
    if !allowedExtensions[ext] {
        return "", "", nil, 0, 0, &ImageValidationError{Message: fmt.Sprintf("File extension '%s' is not allowed. Allowed extensions: .jpg, .jpeg, .png, .gif, .webp", ext)}
    }

    // Verify magic bytes
    expectedMagic, ok := magicBytes[ext]
    if !ok {
        return "", "", nil, 0, 0, &ImageValidationError{Message: "Unknown file extension"}
    }
    if len(data) < len(expectedMagic) {
        return "", "", nil, 0, 0, &ImageValidationError{Message: "File is too small to be a valid image"}
    }
    if !bytes.HasPrefix(data, expectedMagic) {
        return "", "", nil, 0, 0, &ImageValidationError{Message: "File header does not match the expected format for the given extension"}
    }

    // Additional check for WebP: verify "WEBP" at bytes 8-11
    if ext == ".webp" {
        if len(data) < 12 {
            return "", "", nil, 0, 0, &ImageValidationError{Message: "File is too small to be a valid WebP image"}
        }
        if string(data[8:12]) != "WEBP" {
            return "", "", nil, 0, 0, &ImageValidationError{Message: "File is not a valid WebP image"}
        }
    }

    // Decode image to validate structure and get dimensions
    reader := bytes.NewReader(data)
    img, format, err := image.Decode(reader)
    if err != nil {
        return "", "", nil, 0, 0, &ImageValidationError{Message: fmt.Sprintf("Failed to decode image: %v", err)}
    }

    // Validate dimensions
    bounds := img.Bounds()
    width = bounds.Dx()
    height = bounds.Dy()

    if width <= 0 || height <= 0 {
        return "", "", nil, 0, 0, &ImageValidationError{Message: "Image has invalid dimensions (width or height <= 0)"}
    }
    if width > MaxImageWidth || height > MaxImageHeight {
        return "", "", nil, 0, 0, &ImageValidationError{Message: fmt.Sprintf("Image dimensions exceed maximum allowed size of %dx%d pixels", MaxImageWidth, MaxImageHeight)}
    }

    // Re-encode image to sanitize and strip EXIF/metadata
    var outputBuffer bytes.Buffer
    var outputExt string

    switch format {
    case "jpeg":
        err = jpeg.Encode(&outputBuffer, img, &jpeg.Options{Quality: 90})
        contentType = "image/jpeg"
        outputExt = ".jpg"
    case "png":
        err = png.Encode(&outputBuffer, img)
        contentType = "image/png"
        outputExt = ".png"
    case "gif", "webp":
        // Convert GIF and WebP to PNG for sanitization
        err = png.Encode(&outputBuffer, img)
        contentType = "image/png"
        outputExt = ".png"
    default:
        // For any other format, convert to PNG
        err = png.Encode(&outputBuffer, img)
        contentType = "image/png"
        outputExt = ".png"
    }

    if err != nil {
        return "", "", nil, 0, 0, &ImageValidationError{Message: fmt.Sprintf("Failed to re-encode image: %v", err)}
    }

    // Generate random filename (16 random bytes = 32 hex characters)
    randomBytes := make([]byte, 16)
    if _, err := rand.Read(randomBytes); err != nil {
        return "", "", nil, 0, 0, errors.New("failed to generate random filename")
    }
    filename = hex.EncodeToString(randomBytes) + outputExt

    return filename, contentType, outputBuffer.Bytes(), width, height, nil
}

// saveImage stores an image in the database
func saveImage(filename, contentType string, data []byte, width, height int) error {
    _, err := db.Exec(
        "INSERT INTO Images (filename, content_type, data, width, height) VALUES (?, ?, ?, ?, ?)",
        filename, contentType, data, width, height,
    )
    return err
}

// getImage retrieves an image from the database by filename
func getImage(filename string) (*Image, error) {
    var img Image
    err := db.QueryRow(
        "SELECT id, filename, content_type, data, width, height, created_at FROM Images WHERE filename = ?",
        filename,
    ).Scan(&img.ID, &img.Filename, &img.ContentType, &img.Data, &img.Width, &img.Height, &img.CreatedAt)
    if err != nil {
        return nil, err
    }
    return &img, nil
}
