package products

import (
	"encoding/json"
	"net/http"
)

// Example handler for API
func GetProducts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(
		[]map[string]interface{}{
			{"id": 1, "name": "Product 1", "price": 100},
			{"id": 2, "name": "Product 2", "price": 200},
			{"id": 3, "name": "Product 3", "price": 300},
		},
	)
}
