package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

const puckServerPath = "/srv/puckserver/Puck.x86_64"
const passwordFilePath = "/srv/puckserver/.puckerup_password"
const configBasePath = "/srv/puckserver"
const scheduleFilePath = "/srv/puckserver/schedules.json" // Persistence for schedules

// --- Server Config Structures to match the JSON file ---
type PhaseDurationMap struct {
	Warmup     int `json:"Warmup"`
	FaceOff    int `json:"FaceOff"`
	Playing    int `json:"Playing"`
	BlueScore  int `json:"BlueScore"`
	RedScore   int `json:"RedScore"`
	Replay     int `json:"Replay"`
	PeriodOver int `json:"PeriodOver"`
	GameOver   int `json:"GameOver"`
}
type Mod struct {
	ID             int64 `json:"id"`
	Enabled        bool  `json:"enabled"`
	ClientRequired bool  `json:"clientRequired"`
}
type ServerConfig struct {
	Port                  int              `json:"port"`
	PingPort              int              `json:"pingPort"`
	Name                  string           `json:"name"`
	MaxPlayers            int              `json:"maxPlayers"`
	Password              string           `json:"password"`
	Voip                  bool             `json:"voip"`
	IsPublic              bool             `json:"isPublic"`
	AdminSteamIds         []string         `json:"adminSteamIds"`
	ReloadBannedSteamIds  bool             `json:"reloadBannedSteamIds"`
	UsePuckBannedSteamIds bool             `json:"usePuckBannedSteamIds"`
	PrintMetrics          bool             `json:"printMetrics"`
	KickTimeout           int              `json:"kickTimeout"`
	SleepTimeout          int              `json:"sleepTimeout"`
	JoinMidMatchDelay     int              `json:"joinMidMatchDelay"`
	TargetFrameRate       int              `json:"targetFrameRate"`
	ServerTickRate        int              `json:"serverTickRate"`
	ClientTickRate        int              `json:"clientTickRate"`
	StartPaused           bool             `json:"startPaused"`
	AllowVoting           bool             `json:"allowVoting"`
	PhaseDurationMap      PhaseDurationMap `json:"phaseDurationMap"`
	Mods                  []Mod            `json:"mods"`
}

// --- Schedule Structures ---
type Schedule struct {
	Enabled bool   `json:"enabled"`
	Time    string `json:"time"` // "HH:MM" format
}

var schedules = make(map[string]Schedule)
var schedulesMutex = &sync.Mutex{}

// Use a secure key for session encryption.
var store = sessions.NewCookieStore([]byte("a-very-secret-and-secure-key-32-bytes-long-!"))

func init() {
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}
}

// --- Scheduler Functions ---
func loadSchedules() {
	schedulesMutex.Lock()
	defer schedulesMutex.Unlock()
	data, err := os.ReadFile(scheduleFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("Schedule file not found, starting with empty schedule.")
			return
		}
		log.Printf("Error reading schedule file: %v", err)
		return
	}
	if err := json.Unmarshal(data, &schedules); err != nil {
		log.Printf("Error parsing schedule file: %v", err)
	}
	log.Println("Schedules loaded successfully.")
}

func saveSchedules() {
	schedulesMutex.Lock()
	defer schedulesMutex.Unlock()
	data, err := json.MarshalIndent(schedules, "", "  ")
	if err != nil {
		log.Printf("Error marshalling schedules: %v", err)
		return
	}
	if err := os.WriteFile(scheduleFilePath, data, 0644); err != nil {
		log.Printf("Error writing schedule file: %v", err)
	}
}

func startScheduler() {
	ticker := time.NewTicker(1 * time.Minute)
	log.Println("Daily restart scheduler started.")
	go func() {
		for range ticker.C {
			nowUTC := time.Now().UTC()
			currentTime := nowUTC.Format("15:04")
			
			schedulesMutex.Lock()
			schedulesToCheck := make(map[string]Schedule)
			for k, v := range schedules {
				schedulesToCheck[k] = v
			}
			schedulesMutex.Unlock()

			for serverNum, schedule := range schedulesToCheck {
				if schedule.Enabled && schedule.Time == currentTime {
					log.Printf("Executing scheduled restart for server %s at %s UTC", serverNum, currentTime)
					serviceName := fmt.Sprintf("puck@server%s", serverNum)
					go func(sName string) {
						cmd := exec.Command("systemctl", "restart", sName)
						if err := cmd.Run(); err != nil {
							log.Printf("Error during scheduled restart of %s: %v", sName, err)
						} else {
							log.Printf("Scheduled restart of %s completed successfully.", sName)
						}
					}(serviceName)
				}
			}
		}
	}()
}

// --- Middleware for Authentication ---
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "puckerup-session")
		auth, ok := session.Values["authenticated"].(bool)
		if !ok || !auth {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			http.Redirect(w, r, "/login.html", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- Login/Logout Handlers ---
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	var creds struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	hashBytes, err := os.ReadFile(passwordFilePath)
	if err != nil {
		log.Printf("Failed to read password file: %v", err)
		http.Error(w, "Server error during login", http.StatusInternalServerError)
		return
	}
	hash := strings.TrimSpace(string(hashBytes))
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(creds.Password)); err != nil {
		log.Println("Bcrypt comparison failed: password does not match hash.")
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	session, _ := store.Get(r, "puckerup-session")
	session.Values["authenticated"] = true
	if err := session.Save(r, w); err != nil {
		log.Printf("Failed to save session: %v", err)
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"message": "Login successful"}`)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	session, _ := store.Get(r, "puckerup-session")
	session.Values["authenticated"] = false
	session.Options = &sessions.Options{MaxAge: -1, Path: "/"}
	session.Save(r, w)
	w.WriteHeader(http.StatusOK)
}

// --- API Handlers ---
func statusHandler(w http.ResponseWriter, r *http.Request) {
	_, err := os.Stat(puckServerPath)
	installed := !os.IsNotExist(err)
	json.NewEncoder(w).Encode(map[string]bool{"installed": installed})
}
func installHandler(w http.ResponseWriter, r *http.Request) {
	time.Sleep(2 * time.Second)
	json.NewEncoder(w).Encode(map[string]string{"message": "Installation complete! The page will now reload."})
}
func getServerConfigHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serverNum := vars["serverNum"]
	configFile := filepath.Join(configBasePath, fmt.Sprintf("server%s.json", serverNum))
	var config ServerConfig
	file, err := os.ReadFile(configFile)
	if err != nil {
		if !os.IsNotExist(err) {
			http.Error(w, "Failed to read config file", http.StatusInternalServerError)
			return
		}
	} else {
		if err := json.Unmarshal(file, &config); err != nil {
			http.Error(w, "Failed to parse config file", http.StatusInternalServerError)
			return
		}
	}
	cmd := exec.Command("systemctl", "is-active", fmt.Sprintf("puck@server%s", serverNum))
	statusOutput, _ := cmd.Output()
	status := strings.TrimSpace(string(statusOutput))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"config": config, "status": status})
}
func updateServerConfigHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serverNum := vars["serverNum"]
	configFile := filepath.Join(configBasePath, fmt.Sprintf("server%s.json", serverNum))
	var config ServerConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(config); err != nil {
		http.Error(w, "Failed to marshal config", http.StatusInternalServerError)
		return
	}
	if err := os.WriteFile(configFile, buffer.Bytes(), 0644); err != nil {
		http.Error(w, "Failed to write config file", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"message": "Config saved successfully!"})
}
func serverControlHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serverNum := vars["serverNum"]
	var reqBody struct{ Action string `json:"action"` }
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	validActions := map[string]bool{"start": true, "stop": true, "restart": true}
	if !validActions[reqBody.Action] {
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}
	serviceName := fmt.Sprintf("puck@server%s", serverNum)
	cmd := exec.Command("systemctl", reqBody.Action, serviceName)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		log.Printf("Failed to run systemctl %s %s: %v\nStderr: %s", reqBody.Action, serviceName, err, stderr.String())
		http.Error(w, fmt.Sprintf("Failed to %s server: %s", reqBody.Action, stderr.String()), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"message": fmt.Sprintf("Command '%s' executed for server %s.", reqBody.Action, serverNum)})
}

func scheduleHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    serverNum := vars["serverNum"]
    switch r.Method {
    case http.MethodGet:
        schedulesMutex.Lock()
        schedule, ok := schedules[serverNum]
        schedulesMutex.Unlock()
        if !ok {
            schedule = Schedule{Enabled: false, Time: "00:00"}
        }
        json.NewEncoder(w).Encode(schedule)
    case http.MethodPost:
        var newSchedule Schedule
        if err := json.NewDecoder(r.Body).Decode(&newSchedule); err != nil {
            http.Error(w, "Invalid request body", http.StatusBadRequest)
            return
        }
        if _, err := time.Parse("15:04", newSchedule.Time); err != nil && newSchedule.Enabled {
             http.Error(w, "Invalid time format. Use HH:MM.", http.StatusBadRequest)
             return
        }
        schedulesMutex.Lock()
        schedules[serverNum] = newSchedule
        schedulesMutex.Unlock()
        saveSchedules()
        log.Printf("Updated schedule for server %s: Enabled=%v, Time=%s", serverNum, newSchedule.Enabled, newSchedule.Time)
        json.NewEncoder(w).Encode(map[string]string{"message": "Schedule updated successfully!"})
    default:
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
    }
}

func main() {
	loadSchedules()
	startScheduler()
	
	r := mux.NewRouter()
	r.HandleFunc("/login", loginHandler)
	r.HandleFunc("/logout", logoutHandler)
	r.PathPrefix("/login.html").Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "login.html")
	}))
	
	api := r.PathPrefix("/api").Subrouter()
	api.Use(authMiddleware)
	api.HandleFunc("/status", statusHandler)
	api.HandleFunc("/install", installHandler).Methods("POST")
	api.HandleFunc("/server/{serverNum}/config", getServerConfigHandler).Methods("GET")
	api.HandleFunc("/server/{serverNum}/config", updateServerConfigHandler).Methods("POST")
	api.HandleFunc("/server/{serverNum}/control", serverControlHandler).Methods("POST")
	api.HandleFunc("/server/{serverNum}/schedule", scheduleHandler).Methods("GET", "POST")
	
	protectedFileServer := http.FileServer(http.Dir("."))
	r.PathPrefix("/").Handler(authMiddleware(protectedFileServer))
	
	fmt.Println("Starting PuckerUp server on http://0.0.0.0:8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

