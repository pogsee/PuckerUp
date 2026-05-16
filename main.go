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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/robfig/cron/v3"
	"golang.org/x/crypto/bcrypt"
)

const puckServerPath = "/srv/puckserver/Puck"
const passwordFilePath = "/srv/puckserver/.puckerup_password"
const configBasePath = "/srv/puckserver"
const publicGameModeConfigPath = "/srv/puckserver/public_game_mode_config.json"
const schedulesFilePath = "/srv/puckserver/schedules.json"

// --- Server Config Structures to match the JSON file ---
type PhaseDurationMap struct {
	None         int `json:"None"`
	Warmup       int `json:"Warmup"`
	PreGame      int `json:"PreGame"`
	FaceOff      int `json:"FaceOff"`
	Play         int `json:"Play"`
	BlueScore    int `json:"BlueScore"`
	RedScore     int `json:"RedScore"`
	Replay       int `json:"Replay"`
	Intermission int `json:"Intermission"`
	GameOver     int `json:"GameOver"`
	PostGame     int `json:"PostGame"`
}
type Mod struct {
	ID             int64 `json:"id"`
	Enabled        bool  `json:"enabled"`
	ClientRequired bool  `json:"clientRequired"`
}
type ServerConfig struct {
	Port                  int      `json:"port"`
	Name                  string   `json:"name"`
	MaxPlayers            int      `json:"maxPlayers"`
	Password              string   `json:"password"`
	UseVoip               bool     `json:"useVoip"`
	IsPublic              bool     `json:"isPublic"`
	UseWhitelist          bool     `json:"useWhitelist"`
	GameMode              string   `json:"gameMode"`
	Level                 string   `json:"level"`
	AdminSteamIds         []string `json:"adminSteamIds"`
	ReloadBannedSteamIds  bool     `json:"reloadBannedSteamIds"`
	UsePuckBannedSteamIds bool     `json:"usePuckBannedSteamIds"`
	PrintMetrics          bool     `json:"printMetrics"`
	KickTimeout           int      `json:"kickTimeout"`
	SleepTimeout          int      `json:"sleepTimeout"`
	JoinMidMatchDelay     int      `json:"joinMidMatchDelay"`
	ClientTickRate        int      `json:"clientTickRate"`
	StartPaused           bool     `json:"startPaused"`
	AllowVoting           bool     `json:"allowVoting"`
	Mods                  []Mod    `json:"mods"`
}
type PublicGameModeConfig struct {
	PhaseDurationMap PhaseDurationMap `json:"phaseDurationMap"`
	SpawnDelay       int              `json:"spawnDelay"`
	MaxPeriods       int              `json:"maxPeriods"`
}

// --- NEW: Rate Limiter ---
type loginAttempt struct {
	failures int
	lastTry  time.Time
}

var (
	loginAttempts = make(map[string]loginAttempt)
	loginMutex    = &sync.Mutex{}
)

const (
	maxLoginFailures = 5
	lockoutDuration  = 10 * time.Minute
)

// Use a secure key for session encryption.
var store = sessions.NewCookieStore([]byte("a-very-secret-and-secure-key-32-bytes-long-!"))

// --- Scheduler ---
type Schedule struct {
	Enabled bool   `json:"enabled"`
	Time    string `json:"time"` // HH:mm format
}

var (
	scheduler    = cron.New()
	scheduleMap  = make(map[string]Schedule)
	scheduleLock = &sync.Mutex{}
)

func init() {
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400, // 24 hours
		HttpOnly: true,
		Secure:   false, // Set to true if deploying with HTTPS
		SameSite: http.SameSiteLaxMode,
	}

	// Periodically clean up old login attempt entries
	go func() {
		for range time.Tick(30 * time.Minute) {
			loginMutex.Lock()
			for ip, attempt := range loginAttempts {
				if time.Since(attempt.lastTry) > lockoutDuration*2 { // Clean up entries older than 2x lockout
					delete(loginAttempts, ip)
				}
			}
			loginMutex.Unlock()
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

	// --- NEW: Rate Limiting Check ---
	ip := strings.Split(r.RemoteAddr, ":")[0]
	loginMutex.Lock()
	attempt, ok := loginAttempts[ip]
	if ok && attempt.failures >= maxLoginFailures && time.Since(attempt.lastTry) < lockoutDuration {
		loginMutex.Unlock()
		log.Printf("Blocked login attempt from IP: %s", ip)
		http.Error(w, "Too many failed login attempts. Please try again later.", http.StatusTooManyRequests)
		return
	}
	loginMutex.Unlock()
	// --- END NEW ---

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

	log.Println("--- AUTHENTICATION ATTEMPT ---")
	log.Printf("Password received (length %d)", len(creds.Password))
	log.Printf("Hash from file    (length %d): \"%s\"", len(hash), hash)

	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(creds.Password))
	if err != nil {
		log.Println("Bcrypt comparison failed: password does not match hash.")
		// --- NEW: Record Failed Attempt ---
		loginMutex.Lock()
		attempt, _ := loginAttempts[ip]
		attempt.failures++
		attempt.lastTry = time.Now()
		loginAttempts[ip] = attempt
		loginMutex.Unlock()
		// --- END NEW ---
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// --- NEW: Clear Failed Attempts on Success ---
	loginMutex.Lock()
	delete(loginAttempts, ip)
	loginMutex.Unlock()
	// --- END NEW ---

	session, _ := store.Get(r, "puckerup-session")
	session.Values["authenticated"] = true
	if err = session.Save(r, w); err != nil {
		log.Printf("Failed to save session: %v", err)
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}
	log.Println("Successful login")
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

	// Create a new session options instance to avoid modifying the global one
	newOptions := *store.Options
	newOptions.MaxAge = -1 // Expire the cookie immediately
	session.Options = &newOptions

	session.Save(r, w)
	w.WriteHeader(http.StatusOK)
}

// --- API Handlers ---
func statusHandler(w http.ResponseWriter, r *http.Request) {
	_, err := os.Stat(puckServerPath)
	installed := !os.IsNotExist(err)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"installed": installed})
}

func installHandler(w http.ResponseWriter, r *http.Request) {
	time.Sleep(2 * time.Second)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Installation complete! The page will now reload."})
}

func defaultPublicGameModeConfig() PublicGameModeConfig {
	return PublicGameModeConfig{
		PhaseDurationMap: PhaseDurationMap{
			None:         0,
			Warmup:       60,
			PreGame:      10,
			FaceOff:      5,
			Play:         300,
			BlueScore:    5,
			RedScore:     5,
			Replay:       10,
			Intermission: 10,
			GameOver:     30,
			PostGame:     10,
		},
		SpawnDelay: 5,
		MaxPeriods: 3,
	}
}

func defaultServerConfig(serverNum string) ServerConfig {
	port := 30609
	if num, err := strconv.Atoi(serverNum); err == nil && num > 1 {
		port += num - 1
	}

	return ServerConfig{
		Port:                  port,
		Name:                  fmt.Sprintf("Puck Server %s", serverNum),
		MaxPlayers:            10,
		UseVoip:               false,
		IsPublic:              true,
		UseWhitelist:          true,
		GameMode:              "public",
		Level:                 "default",
		AdminSteamIds:         []string{},
		ReloadBannedSteamIds:  true,
		UsePuckBannedSteamIds: true,
		PrintMetrics:          true,
		KickTimeout:           1800,
		SleepTimeout:          900,
		JoinMidMatchDelay:     10,
		ClientTickRate:        360,
		StartPaused:           false,
		AllowVoting:           true,
		Mods:                  []Mod{},
	}
}

func getPublicGameModeConfigHandler(w http.ResponseWriter, r *http.Request) {
	config := defaultPublicGameModeConfig()
	file, err := os.ReadFile(publicGameModeConfigPath)
	if err == nil {
		if err := json.Unmarshal(file, &config); err != nil {
			http.Error(w, "Invalid public game mode config", http.StatusInternalServerError)
			return
		}
	} else if !os.IsNotExist(err) {
		log.Printf("Failed to read public game mode config: %v", err)
		http.Error(w, "Failed to read public game mode config", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func updatePublicGameModeConfigHandler(w http.ResponseWriter, r *http.Request) {
	var config PublicGameModeConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	encoder.Encode(config)

	if err := os.WriteFile(publicGameModeConfigPath, buffer.Bytes(), 0644); err != nil {
		log.Printf("Failed to write public game mode config: %v", err)
		http.Error(w, "Failed to save public game mode config", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Public game mode config saved successfully!"})
}

func getServerConfigHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serverNum := vars["serverNum"]
	configFile := filepath.Join(configBasePath, fmt.Sprintf("server%s.json", serverNum))

	config := defaultServerConfig(serverNum)
	file, err := os.ReadFile(configFile)
	if err == nil {
		json.Unmarshal(file, &config)
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
	json.NewDecoder(r.Body).Decode(&config)

	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	encoder.Encode(config)

	os.WriteFile(configFile, buffer.Bytes(), 0644)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Config saved successfully!"})
}

func serverControlHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serverNum := vars["serverNum"]
	var reqBody struct {
		Action string `json:"action"`
	}
	json.NewDecoder(r.Body).Decode(&reqBody)

	serviceName := fmt.Sprintf("puck@server%s", serverNum)
	cmd := exec.Command("systemctl", reqBody.Action, serviceName)
	stderr, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Failed to run systemctl %s %s: %v\nOutput: %s", reqBody.Action, serviceName, err, string(stderr))
		http.Error(w, fmt.Sprintf("Failed to %s server: %s", reqBody.Action, string(stderr)), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": fmt.Sprintf("Command '%s' executed for server %s.", reqBody.Action, serverNum)})
}

// --- Schedule Handlers ---
func getScheduleHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serverNum := vars["serverNum"]
	scheduleLock.Lock()
	defer scheduleLock.Unlock()
	schedule, ok := scheduleMap[serverNum]
	if !ok {
		schedule = Schedule{Enabled: false, Time: "03:00"}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(schedule)
}

func updateScheduleHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serverNum := vars["serverNum"]
	var schedule Schedule
	if err := json.NewDecoder(r.Body).Decode(&schedule); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	updateAndSaveSchedules(serverNum, schedule)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Schedule updated successfully!"})
}

func restartServerJob(serverNum string) func() {
	return func() {
		log.Printf("Executing scheduled restart for server %s...", serverNum)
		cmd := exec.Command("systemctl", "restart", fmt.Sprintf("puck@server%s", serverNum))
		err := cmd.Run()
		if err != nil {
			log.Printf("ERROR: Scheduled restart for server %s failed: %v", serverNum, err)
		} else {
			log.Printf("Scheduled restart for server %s completed.", serverNum)
		}
	}
}

func loadAndApplySchedules() {
	scheduleLock.Lock()
	defer scheduleLock.Unlock()
	log.Println("Loading and applying schedules...")

	file, err := os.ReadFile(schedulesFilePath)
	if err == nil {
		json.Unmarshal(file, &scheduleMap)
	}

	// Remove all old entries from the scheduler
	for _, entry := range scheduler.Entries() {
		scheduler.Remove(entry.ID)
	}

	for serverNum, schedule := range scheduleMap {
		if schedule.Enabled {
			t, err := time.Parse("15:04", schedule.Time)
			if err == nil {
				cronSpec := fmt.Sprintf("%d %d * * *", t.Minute(), t.Hour())
				id, err := scheduler.AddFunc(cronSpec, restartServerJob(serverNum))
				if err != nil {
					log.Printf("Error adding schedule for server %s: %v", serverNum, err)
				} else {
					log.Printf("Scheduled daily restart for server %s at %s UTC (Entry ID: %d)", serverNum, schedule.Time, id)
				}
			}
		}
	}
}

func updateAndSaveSchedules(serverNum string, schedule Schedule) {
	scheduleLock.Lock()
	defer scheduleLock.Unlock()
	scheduleMap[serverNum] = schedule
	data, err := json.MarshalIndent(scheduleMap, "", "  ")
	if err == nil {
		os.WriteFile(schedulesFilePath, data, 0644)
	}
	// Reload all schedules to apply the change
	go loadAndApplySchedules()
}

func main() {
	r := mux.NewRouter()

	// --- Public routes ---
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/logout", logoutHandler).Methods("POST")
	r.PathPrefix("/login.html").Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "login.html")
	}))

	// --- Protected routes ---
	api := r.PathPrefix("/api").Subrouter()
	api.Use(authMiddleware)
	api.HandleFunc("/status", statusHandler)
	api.HandleFunc("/install", installHandler).Methods("POST")
	api.HandleFunc("/public-game-mode-config", getPublicGameModeConfigHandler).Methods("GET")
	api.HandleFunc("/public-game-mode-config", updatePublicGameModeConfigHandler).Methods("POST")
	api.HandleFunc("/server/{serverNum}/config", getServerConfigHandler).Methods("GET")
	api.HandleFunc("/server/{serverNum}/config", updateServerConfigHandler).Methods("POST")
	api.HandleFunc("/server/{serverNum}/control", serverControlHandler).Methods("POST")
	api.HandleFunc("/server/{serverNum}/schedule", getScheduleHandler).Methods("GET")
	api.HandleFunc("/server/{serverNum}/schedule", updateScheduleHandler).Methods("POST")

	protectedFileServer := http.FileServer(http.Dir("."))
	r.PathPrefix("/").Handler(authMiddleware(protectedFileServer))

	// Load schedules from file and start the cron scheduler
	loadAndApplySchedules()
	scheduler.Start()

	port, exists := os.LookupEnv("PUCKERUP_PORT")
	if !exists {
		port = "8080"
	}

	listenAddr := ":" + port
	fmt.Printf("Starting PuckerUp server on http://0.0.0.0%s\n", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, r))
}
