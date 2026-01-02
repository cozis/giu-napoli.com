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

func main() {

	var err error

	indexTemplate := template.Must(template.ParseFiles(
        "templates/base.html",
        "templates/index.html",
    ))

	createTemplate := template.Must(template.ParseFiles(
        "templates/base.html",
        "templates/create.html",
    ))

	postTemplate := template.Must(template.ParseFiles(
        "templates/base.html",
        "templates/post.html",
    ))

    db, err = sql.Open("sqlite3", "./posts.db?_foreign_keys=on")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Ensure schema is created
    _, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT
        )
    `)
    if err != nil {
        log.Fatal(err)
    }

    _, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL UNIQUE,
            content_type TEXT NOT NULL,
            data BLOB NOT NULL,
            width INTEGER NOT NULL,
            height INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `)
    if err != nil {
        log.Fatal(err)
    }

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

        // Parse the form data
        err := r.ParseForm()
        if err != nil {
            http.Error(w, "Bad request", http.StatusBadRequest)
            return
        }

        // Get form values
        csrf    := r.FormValue("csrf")
        title   := r.FormValue("title")
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

        // Insert into database
        _, err = db.Exec(
            "INSERT INTO posts (title, content) VALUES (?, ?)",
            title, content,
        )
        if err != nil {
            http.Error(w, "Database error", http.StatusInternalServerError)
            log.Println(err)
            return
        }

        // Redirect back to home page
        http.Redirect(w, r, "/", http.StatusSeeOther)
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

        postTemplate.ExecuteTemplate(w, "base", post)
    })

    // Image upload handler
    http.HandleFunc("/upload-image", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
            return
        }

        // Limit request body size using MaxBytesReader
        r.Body = http.MaxBytesReader(w, r.Body, MaxUploadSize+1024) // Extra buffer for form overhead

        // Parse multipart form with size limit
        if err := r.ParseMultipartForm(MaxUploadSize); err != nil {
            if err.Error() == "http: request body too large" {
                http.Error(w, "File size exceeds maximum allowed size", http.StatusRequestEntityTooLarge)
                return
            }
            http.Error(w, "Failed to parse form", http.StatusBadRequest)
            return
        }

        // Get the file from the form
        file, header, err := r.FormFile("image")
        if err != nil {
            http.Error(w, "No image file provided", http.StatusBadRequest)
            return
        }
        defer file.Close()

        // Read file data
        data, err := io.ReadAll(file)
        if err != nil {
            http.Error(w, "Failed to read file", http.StatusInternalServerError)
            return
        }

        // Validate and process the image
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

        // Save to database
        if err := saveImage(filename, contentType, processedData, width, height); err != nil {
            http.Error(w, "Failed to save image", http.StatusInternalServerError)
            log.Println(err)
            return
        }

        // Return the filename/URL in JSON response
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusCreated)
        fmt.Fprintf(w, `{"filename":"%s","url":"/images/%s","width":%d,"height":%d}`, filename, filename, width, height)
    })

    // Image serving handler
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

func getPosts() ([]Post, error) {
    rows, err := db.Query("SELECT id, title, content FROM posts")
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var posts []Post
    for rows.Next() {
        var p Post
        err := rows.Scan(&p.ID, &p.Title, &p.Content)
        if err != nil {
            return nil, err
        }
        posts = append(posts, p)
    }

    return posts, rows.Err()
}

func getPost(id int) (*Post, error) {
    var p Post
    err := db.QueryRow("SELECT id, title, content FROM posts WHERE id = ?", id).Scan(&p.ID, &p.Title, &p.Content)
    if err != nil {
        return nil, err
    }
    return &p, nil
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
        "INSERT INTO images (filename, content_type, data, width, height) VALUES (?, ?, ?, ?, ?)",
        filename, contentType, data, width, height,
    )
    return err
}

// getImage retrieves an image from the database by filename
func getImage(filename string) (*Image, error) {
    var img Image
    err := db.QueryRow(
        "SELECT id, filename, content_type, data, width, height, created_at FROM images WHERE filename = ?",
        filename,
    ).Scan(&img.ID, &img.Filename, &img.ContentType, &img.Data, &img.Width, &img.Height, &img.CreatedAt)
    if err != nil {
        return nil, err
    }
    return &img, nil
}