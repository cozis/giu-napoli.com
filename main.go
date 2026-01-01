package main

import (
    "crypto/rand"
    "database/sql"
    "encoding/base64"
    "html/template"
    "io"
    "log"
    "net/http"
    "os"
    "path/filepath"
    "strconv"
    "strings"
    "sync"
    "time"

    _ "github.com/mattn/go-sqlite3"
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

    db, err = sql.Open("sqlite3", "./posts.db?_foreign_keys=on")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Ensure schema is created
    _, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS Posts (
            id      INTEGER   PRIMARY KEY AUTOINCREMENT,
            title   TEXT      NOT NULL,
            content TEXT,
            image   TEXT,
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

    // Add image column if it doesn't exist (for existing databases)
    db.Exec(`ALTER TABLE Posts ADD COLUMN image TEXT`)
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

        // Parse the multipart form data (10MB max)
        err := r.ParseMultipartForm(10 << 20)
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

        // Handle image upload
        var imageName string
        file, header, err := r.FormFile("image")
        if err == nil {
            defer file.Close()

            // Validate file extension
            ext := strings.ToLower(filepath.Ext(header.Filename))
            allowedExts := map[string]bool{".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".webp": true}
            if !allowedExts[ext] {
                http.Error(w, "Invalid image format", http.StatusBadRequest)
                return
            }

            // Create uploads directory if it doesn't exist
            if err := os.MkdirAll("uploads", 0755); err != nil {
                http.Error(w, "Server error", http.StatusInternalServerError)
                log.Println(err)
                return
            }

            // Generate unique filename
            imageName = generateRandomToken() + ext
            destPath := filepath.Join("uploads", imageName)

            // Create destination file
            destFile, err := os.Create(destPath)
            if err != nil {
                http.Error(w, "Server error", http.StatusInternalServerError)
                log.Println(err)
                return
            }
            defer destFile.Close()

            // Copy uploaded file to destination
            if _, err := io.Copy(destFile, file); err != nil {
                http.Error(w, "Server error", http.StatusInternalServerError)
                log.Println(err)
                return
            }
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
        parentPostIDStr  := r.FormValue("parent_post")
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

        parentPostID, err := strconv.Atoi(parentPostIDStr)
        if err != nil {
            http.Error(w, "Parent post ID is required", http.StatusBadRequest)
            return
        }

        var parentReplyID *int
        if parentReplyIDStr != "" {
	       	tmp, err := strconv.Atoi(parentReplyIDStr)
	        if err != nil {
	            http.Error(w, "Invalid reply ID", http.StatusBadRequest)
	            return
	        }
			parentReplyID = &tmp
        }

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

    // Serve uploaded images
    http.Handle("/uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir("uploads"))))

    log.Fatal(http.ListenAndServe(":8080", nil))
}
