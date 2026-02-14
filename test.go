package main
import ("log"; "net/http")
func main() {
    log.Println("Server starting on :8080")
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Working!"))
    })
    log.Fatal(http.ListenAndServe(":8080", nil))
}
