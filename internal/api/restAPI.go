package api

import (
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
)

func main() {

}

func CreateRouter() *chi.Mux {
	router := chi.NewRouter()

	router.Use(middleware.RequestID)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(render.SetContentType(render.ContentTypeJSON))
	return router
}
func basicTests(r *chi.Mux) {
	//tests server and router
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(".root"))
	})
	//tests basic endpoint for connetivity
	r.Get("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("pong"))
	})
	//test recovery capabilities
	r.Get("/panic", func(w http.ResponseWriter, r *http.Request) {
		panic("test")
	})
}

func routes(r *chi.Mux) {
	r.Route("/packets", func(router chi.Router) {
		r.Get("/", getPackets)
		r.Route("/{src_ip}", func(r chi.Router) {
			r.Get("/", getPacketsWithIP)
		})
	})

	log.Println("Listening on port 8080")
	err := http.ListenAndServe(":8080", r)
	if err != nil {
		log.Fatal(err)
	}
}

func getPackets() {}

func getPacketsWithIP() {}
