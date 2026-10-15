package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type User struct {
	ID          int
	Email, Role string
}
type Product struct {
	ID                          int
	Name, Category, Description string
	Price                       float64
}
type Order struct {
	ID                               int
	Customer, Address, Phone, Status string
	Total                            float64
	Created                          string
}
type PageData struct {
	User     *User
	Products []Product
	Orders   []Order
	Message  string
	Error    string
	IsAdmin  bool
	CSRF     string
}
type Session struct {
	User    User
	CSRF    string
	Expires time.Time
}

var db *sql.DB
var sessions = map[string]Session{}
var sessionsMu sync.Mutex
var templates = template.Must(template.ParseGlob("templates/*.html"))

func main() {
	path := os.Getenv("DB_PATH")
	if path == "" {
		path = "bakery.db"
	}
	var err error
	db, err = sql.Open("sqlite", path)
	if err != nil {
		log.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if err = initDB(); err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", home)
	mux.HandleFunc("/register", register)
	mux.HandleFunc("/login", login)
	mux.HandleFunc("/logout", logout)
	mux.HandleFunc("/order", createOrder)
	mux.HandleFunc("/my-orders", myOrders)
	mux.HandleFunc("/admin", adminPage)
	mux.HandleFunc("/admin/product/save", saveProduct)
	mux.HandleFunc("/admin/product/delete", deleteProduct)
	mux.HandleFunc("/admin/order/status", updateOrderStatus)
	addr := os.Getenv("PORT")
	if addr == "" {
		addr = "8080"
	}
	log.Printf("Sweetie Bakery running on :%s", addr)
	log.Fatal(http.ListenAndServe(":"+addr, securityHeaders(mux)))
}

func initDB() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user')`,
		`CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, category TEXT NOT NULL, description TEXT NOT NULL, price REAL NOT NULL CHECK(price >= 0))`,
		`CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, customer TEXT NOT NULL, address TEXT NOT NULL, phone TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'รอดำเนินการ', total REAL NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id))`,
		`CREATE TABLE IF NOT EXISTS order_items (id INTEGER PRIMARY KEY AUTOINCREMENT, order_id INTEGER NOT NULL, product_id INTEGER NOT NULL, product_name TEXT NOT NULL, quantity INTEGER NOT NULL, price REAL NOT NULL, FOREIGN KEY(order_id) REFERENCES orders(id))`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("สร้างตารางไม่สำเร็จ: %w", err)
		}
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM products").Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		products := []Product{
			{Name: "Strawberry Shortcake", Category: "เค้ก", Description: "เค้กวานิลลาครีมสดและสตรอว์เบอร์รี", Price: 89},
			{Name: "Chocolate Cake", Category: "เค้ก", Description: "เค้กช็อกโกแลตเข้มข้น", Price: 95},
			{Name: "Blueberry Cheesecake", Category: "เค้ก", Description: "ชีสเค้กเนื้อนุ่มซอสบลูเบอร์รี", Price: 99},
			{Name: "Japanese Soft Cake", Category: "เค้ก", Description: "เค้กญี่ปุ่นเนื้อนุ่มละมุน", Price: 79},
			{Name: "Butter Croissant", Category: "ขนมปัง", Description: "ครัวซองต์เนยหอมกรอบ", Price: 55},
			{Name: "Chocolate Bread", Category: "ขนมปัง", Description: "ขนมปังไส้ช็อกโกแลต", Price: 45},
			{Name: "Garlic Bread", Category: "ขนมปัง", Description: "ขนมปังกระเทียมอบหอม", Price: 49},
			{Name: "Iced Cocoa", Category: "เครื่องดื่ม", Description: "โกโก้เย็นรสเข้ม", Price: 55},
			{Name: "Matcha Latte", Category: "เครื่องดื่ม", Description: "มัทฉะลาเต้หอมชาเขียว", Price: 65},
			{Name: "Iced Caramel Latte", Category: "เครื่องดื่ม", Description: "กาแฟนมคาราเมลเย็น", Price: 70},
		}
		for _, p := range products {
			if _, err := db.Exec("INSERT INTO products(name,category,description,price) VALUES(?,?,?,?)", p.Name, p.Category, p.Description, p.Price); err != nil {
				return err
			}
		}
	}
	// Demo admin account. Change this password before public deployment.
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM users WHERE email=?", "admin@bakery.local").Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		hash, err := bcrypt.GenerateFromPassword([]byte("Bakery123!"), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		if _, err = db.Exec("INSERT INTO users(email,password_hash,role) VALUES(?,?,?)", "admin@bakery.local", string(hash), "admin"); err != nil {
			return err
		}
	}
	return nil
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}
func currentUser(r *http.Request) (*Session, string) {
	c, err := r.Cookie("bakery_session")
	if err != nil {
		return nil, ""
	}
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	s, ok := sessions[c.Value]
	if !ok || time.Now().After(s.Expires) {
		delete(sessions, c.Value)
		return nil, ""
	}
	return &s, c.Value
}
func requireLogin(w http.ResponseWriter, r *http.Request) (*Session, bool) {
	s, _ := currentUser(r)
	if s == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil, false
	}
	return s, true
}
func requireAdmin(w http.ResponseWriter, r *http.Request) (*Session, bool) {
	s, ok := requireLogin(w, r)
	if !ok {
		return nil, false
	}
	if s.User.Role != "admin" {
		http.Error(w, "ไม่มีสิทธิ์เข้าถึง", http.StatusForbidden)
		return nil, false
	}
	return s, true
}
func checkCSRF(r *http.Request, s *Session) bool {
	return r.FormValue("csrf") != "" && r.FormValue("csrf") == s.CSRF
}
func render(w http.ResponseWriter, r *http.Request, name string, d PageData) {
	if s, _ := currentUser(r); s != nil {
		d.User = &s.User
		d.CSRF = s.CSRF
	}
	d.IsAdmin = d.User != nil && d.User.Role == "admin"
	if err := templates.ExecuteTemplate(w, name, d); err != nil {
		log.Printf("render: %v", err)
		http.Error(w, "เกิดข้อผิดพลาดในการแสดงหน้าเว็บ", 500)
	}
}
func products() ([]Product, error) {
	rows, err := db.Query("SELECT id,name,category,description,price FROM products ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Product{}
	for rows.Next() {
		var p Product
		if err := rows.Scan(&p.ID, &p.Name, &p.Category, &p.Description, &p.Price); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	p, err := products()
	if err != nil {
		http.Error(w, "อ่านสินค้าไม่สำเร็จ", 500)
		return
	}
	render(w, r, "home.html", PageData{Products: p, Message: r.URL.Query().Get("msg")})
}
func register(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		render(w, r, "auth.html", PageData{Message: "สมัครสมาชิก"})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
	password := r.FormValue("password")
	if len(email) < 5 || !strings.Contains(email, "@") || len(password) < 8 {
		render(w, r, "auth.html", PageData{Error: "กรุณาใส่อีเมลให้ถูกต้องและรหัสผ่านอย่างน้อย 8 ตัว"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "สร้างรหัสผ่านไม่สำเร็จ", 500)
		return
	}
	_, err = db.Exec("INSERT INTO users(email,password_hash,role) VALUES(?,?,?)", email, string(hash), "user")
	if err != nil {
		render(w, r, "auth.html", PageData{Error: "อีเมลนี้ถูกใช้แล้ว หรือข้อมูลไม่ถูกต้อง"})
		return
	}
	http.Redirect(w, r, "/login?msg=สมัครสมาชิกสำเร็จ", http.StatusSeeOther)
}
func login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		render(w, r, "auth.html", PageData{Message: r.URL.Query().Get("msg")})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
	password := r.FormValue("password")
	var u User
	var hash string
	err := db.QueryRow("SELECT id,email,password_hash,role FROM users WHERE email=?", email).Scan(&u.ID, &u.Email, &hash, &u.Role)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		render(w, r, "auth.html", PageData{Error: "อีเมลหรือรหัสผ่านไม่ถูกต้อง"})
		return
	}
	token := randomToken()
	s := Session{User: u, CSRF: randomToken(), Expires: time.Now().Add(12 * time.Hour)}
	sessionsMu.Lock()
	sessions[token] = s
	sessionsMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "bakery_session", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil, MaxAge: 43200})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	s, t := currentUser(r)
	if s != nil && !checkCSRF(r, s) {
		http.Error(w, "คำขอไม่ถูกต้อง", http.StatusForbidden)
		return
	}
	if s != nil {
		sessionsMu.Lock()
		delete(sessions, t)
		sessionsMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "bakery_session", Value: "", Path: "/", HttpOnly: true, MaxAge: -1, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func createOrder(w http.ResponseWriter, r *http.Request) {
	s, ok := requireLogin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	if !checkCSRF(r, s) {
		http.Error(w, "คำขอไม่ถูกต้อง กรุณาโหลดหน้าใหม่", 403)
		return
	}
	productID, err := strconv.Atoi(r.FormValue("product_id"))
	if err != nil {
		http.Error(w, "สินค้าไม่ถูกต้อง", 400)
		return
	}
	qty, err := strconv.Atoi(r.FormValue("quantity"))
	if err != nil || qty < 1 || qty > 20 {
		http.Error(w, "จำนวนสินค้าต้องอยู่ระหว่าง 1-20", 400)
		return
	}
	customer := strings.TrimSpace(r.FormValue("customer"))
	address := strings.TrimSpace(r.FormValue("address"))
	phone := strings.TrimSpace(r.FormValue("phone"))
	if customer == "" || address == "" || len(phone) < 9 || len(customer) > 100 || len(address) > 500 {
		http.Error(w, "กรุณากรอกชื่อ ที่อยู่ และเบอร์โทรให้ครบถ้วน", 400)
		return
	}
	var p Product
	err = db.QueryRow("SELECT id,name,category,description,price FROM products WHERE id=?", productID).Scan(&p.ID, &p.Name, &p.Category, &p.Description, &p.Price)
	if err != nil {
		http.Error(w, "ไม่พบสินค้า", 400)
		return
	}
	tx, err := db.Begin()
	if err != nil {
		http.Error(w, "ไม่สามารถสร้างคำสั่งซื้อได้", 500)
		return
	}
	res, err := tx.Exec("INSERT INTO orders(user_id,customer,address,phone,total) VALUES(?,?,?,?,?)", s.User.ID, customer, address, phone, p.Price*float64(qty))
	if err != nil {
		_ = tx.Rollback()
		http.Error(w, "บันทึกคำสั่งซื้อไม่สำเร็จ", 500)
		return
	}
	id, err := res.LastInsertId()
	if err == nil {
		_, err = tx.Exec("INSERT INTO order_items(order_id,product_id,product_name,quantity,price) VALUES(?,?,?,?,?)", id, p.ID, p.Name, qty, p.Price)
	}
	if err != nil {
		_ = tx.Rollback()
		http.Error(w, "บันทึกรายการสินค้าไม่สำเร็จ", 500)
		return
	}
	if err = tx.Commit(); err != nil {
		http.Error(w, "บันทึกคำสั่งซื้อไม่สำเร็จ", 500)
		return
	}
	http.Redirect(w, r, "/my-orders", http.StatusSeeOther)
}
func myOrders(w http.ResponseWriter, r *http.Request) {
	s, ok := requireLogin(w, r)
	if !ok {
		return
	}
	rows, err := db.Query("SELECT id,customer,address,phone,status,total,created_at FROM orders WHERE user_id=? ORDER BY id DESC", s.User.ID)
	if err != nil {
		http.Error(w, "อ่านคำสั่งซื้อไม่สำเร็จ", 500)
		return
	}
	defer rows.Close()
	out := []Order{}
	for rows.Next() {
		var o Order
		if err := rows.Scan(&o.ID, &o.Customer, &o.Address, &o.Phone, &o.Status, &o.Total, &o.Created); err != nil {
			http.Error(w, "อ่านคำสั่งซื้อไม่สำเร็จ", 500)
			return
		}
		out = append(out, o)
	}
	render(w, r, "orders.html", PageData{Orders: out})
}
func adminPage(w http.ResponseWriter, r *http.Request) {
	_, ok := requireAdmin(w, r)
	if !ok {
		return
	}
	p, err := products()
	if err != nil {
		http.Error(w, "อ่านสินค้าไม่สำเร็จ", 500)
		return
	}
	rows, err := db.Query("SELECT id,customer,address,phone,status,total,created_at FROM orders ORDER BY id DESC")
	if err != nil {
		http.Error(w, "อ่านคำสั่งซื้อไม่สำเร็จ", 500)
		return
	}
	defer rows.Close()
	orders := []Order{}
	for rows.Next() {
		var o Order
		if err := rows.Scan(&o.ID, &o.Customer, &o.Address, &o.Phone, &o.Status, &o.Total, &o.Created); err != nil {
			http.Error(w, "อ่านคำสั่งซื้อไม่สำเร็จ", 500)
			return
		}
		orders = append(orders, o)
	}
	render(w, r, "admin.html", PageData{Products: p, Orders: orders, Message: r.URL.Query().Get("msg")})
}
func saveProduct(w http.ResponseWriter, r *http.Request) {
	s, ok := requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	if !checkCSRF(r, s) {
		http.Error(w, "คำขอไม่ถูกต้อง", 403)
		return
	}
	id, _ := strconv.Atoi(r.FormValue("id"))
	name := strings.TrimSpace(r.FormValue("name"))
	category := r.FormValue("category")
	desc := strings.TrimSpace(r.FormValue("description"))
	price, err := strconv.ParseFloat(r.FormValue("price"), 64)
	if name == "" || len(name) > 100 || desc == "" || len(desc) > 300 || price < 0 || err != nil || !validCategory(category) {
		http.Error(w, "ข้อมูลสินค้าไม่ถูกต้อง", 400)
		return
	}
	if id > 0 {
		_, err = db.Exec("UPDATE products SET name=?,category=?,description=?,price=? WHERE id=?", name, category, desc, price, id)
	} else {
		_, err = db.Exec("INSERT INTO products(name,category,description,price) VALUES(?,?,?,?)", name, category, desc, price)
	}
	if err != nil {
		http.Error(w, "บันทึกสินค้าไม่สำเร็จ", 500)
		return
	}
	http.Redirect(w, r, "/admin?msg=บันทึกสินค้าแล้ว", http.StatusSeeOther)
}
func validCategory(s string) bool {
	return s == "เค้ก" || s == "ขนมปัง" || s == "เครื่องดื่ม"
}
func deleteProduct(w http.ResponseWriter, r *http.Request) {
	s, ok := requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	if !checkCSRF(r, s) {
		http.Error(w, "คำขอไม่ถูกต้อง", 403)
		return
	}
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		http.Error(w, "รหัสสินค้าไม่ถูกต้อง", 400)
		return
	}
	_, err = db.Exec("DELETE FROM products WHERE id=?", id)
	if err != nil {
		http.Error(w, "ลบสินค้าไม่สำเร็จ", 500)
		return
	}
	http.Redirect(w, r, "/admin?msg=ลบสินค้าแล้ว", http.StatusSeeOther)
}
func updateOrderStatus(w http.ResponseWriter, r *http.Request) {
	s, ok := requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	if !checkCSRF(r, s) {
		http.Error(w, "คำขอไม่ถูกต้อง", 403)
		return
	}
	id, err := strconv.Atoi(r.FormValue("id"))
	status := r.FormValue("status")
	switch status {
	case "รอดำเนินการ", "กำลังเตรียม", "จัดส่งแล้ว", "ยกเลิก":
	default:
		http.Error(w, "สถานะไม่ถูกต้อง", 400)
		return
	}
	if err != nil {
		http.Error(w, "รหัสคำสั่งซื้อไม่ถูกต้อง", 400)
		return
	}
	_, err = db.Exec("UPDATE orders SET status=? WHERE id=?", status, id)
	if err != nil {
		http.Error(w, "อัปเดตสถานะไม่สำเร็จ", 500)
		return
	}
	http.Redirect(w, r, "/admin?msg=อัปเดตสถานะแล้ว", http.StatusSeeOther)
}
