package main

import (
    "database/sql"
    "html/template"
    "log"
    "net/http"
    "sync"
    "time"
    "crypto/rand"
    "encoding/base64"

    _ "github.com/mattn/go-sqlite3"
)

type Post struct {
	ID      int
	Title   string
	Content string
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

    db, err = sql.Open("sqlite3", "./posts.db")
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