package main
import (
	"encoding/json"
	"net/http"
)

// adminOnly wraps authenticated and rejects non-admin users.
func (s *server) adminOnly(next http.Handler) http.Handler {
	return s.authenticated(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := requestIdentity(r)
		role, err := s.db.GetUserRole(r.Context(), id.ID)
		if err != nil {
			writeError(w, 500, "internal_error")
			return
		}
		if role != "admin" {
			writeError(w, 403, "admin_required")
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// listCommunityPostsAdmin returns all posts including removed ones, sorted by created_at desc.
// Query params: ?status=active|removed|all&limit=50&offset=0
func (s *server) listCommunityPostsAdmin(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	status := query.Get("status")
	if status == "" {
		status = "all"
	}
	if status != "all" && status != "active" && status != "removed" {
		writeError(w, 400, "invalid_status")
		return
	}
	limit := pageLimit(query)
	offset := pageOffset(query)
	rows, err := s.db.ListCommunityPostsAdmin(r.Context(), status, limit, offset)
	if err != nil {
		writeError(w, 500, "internal_error")
		return
	}
	writeJSON(w, 200, map[string]any{"posts": rows, "limit": limit, "offset": offset})
}

// updateCommunityPostStatus soft-deletes (status=removed) or restores (status=active) a post.
// Body: {"status": "removed"|"active"}
func (s *server) updateCommunityPostStatus(w http.ResponseWriter, r *http.Request) {
	postID := r.PathValue("postID")
	if len(postID) != 36 {
		writeError(w, 400, "invalid_post_id")
		return
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, 400, "invalid_json")
		return
	}
	if body.Status != "active" && body.Status != "removed" {
		writeError(w, 400, "invalid_status")
		return
	}
	exists, err := s.db.UpdateCommunityPostStatus(r.Context(), postID, body.Status)
	if err != nil {
		writeError(w, 500, "internal_error")
		return
	}
	if !exists {
		writeError(w, 404, "post_not_found")
		return
	}
	writeJSON(w, 200, map[string]any{"id": postID, "status": body.Status})
}
