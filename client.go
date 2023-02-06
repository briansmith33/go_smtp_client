package main

import (
	"net"
	"fmt"
	"strconv"
	"bufio"
	"os"
	"time"
	"strings"
	"encoding/base64"
	"crypto/md5"
	"crypto/sha256"
    "encoding/hex"
	"crypto/hmac"
	"github.com/joho/godotenv"
	"log"
)

type Email struct {
	SenderName string
	SenderAddr string
	Recipients []map[string]string
	Cc []map[string]string
	Bcc []map[string]string
	AdditionalHeaders []map[string]string
	Subject string
	Message string
}

func (e *Email) AddRecipient(name string, address string) {
	e.Recipients = append(e.Recipients, map[string]string{"name": name, "address": address})
}

func (e *Email) AddCc(name string, address string) {
	e.Cc = append(e.Cc, map[string]string{"name": name, "address": address})
}

func (e *Email) AddBcc(name string, address string) {
	e.Bcc = append(e.Bcc, map[string]string{"name": name, "address": address})
}

func (e *Email) AddHeader(key string, value string) {
	e.AdditionalHeaders = append(e.AdditionalHeaders, map[string]string{"key": key, "value": value})
}

func (e *Email) ToString() string {
	sender_name := ""
	if (len(e.SenderName) > 0) {
		sender_name = " \""+e.SenderName+"\""
	}

	date := time.Now().Format("Mon, 2 Jan 2006 15:04:05 -0700")
	subject := ""
	if (len(e.Subject) > 0) {
		subject = e.Subject
	}
	message := "From:"+sender_name+" <"+e.SenderAddr+">\r\n"
	message += "To:"
	for _, recipient := range e.Recipients {
		recipient_name := ""
		value, ok := recipient["name"]
		if (ok && len(value) > 0) {
			recipient_name = " \""+value+"\""
		}
		message += recipient_name+" <"+recipient["address"]+">,"
	}
	message = message[:len(message)-1]
	message += "\r\n"
	if (len(e.Cc) > 0) {
		message += "Cc:"
		for _, recipient := range e.Cc {
			recipient_name := ""
			value, ok := recipient["name"]
			if (ok && len(value) > 0) {
				recipient_name = " \""+value+"\""
			}
			message += recipient_name+" <"+recipient["address"]+">,"
		}
		message = message[:len(message)-1]
		message += "\r\n"
	}
	if (len(e.Bcc) > 0) {
		message += "Bcc:"
		for _, recipient := range e.Bcc {
			recipient_name := ""
			value, ok := recipient["name"]
			if (ok && len(value) > 0) {
				recipient_name = " \""+value+"\""
			}
			message += recipient_name+" <"+recipient["address"]+">,"
		}
		message = message[:len(message)-1]
		message += "\r\n"
	}
	for _, header := range e.AdditionalHeaders {
		message += header["key"]+": "+header["value"]+"\r\n"
	}
	message += "Date: "+date+"\r\n"
	message += "Subject: "+subject+"\r\n"
	message += e.Message+"\r\n."
	return message
}

type SMTPClient struct {
	Conn net.Conn
	Host string
	Port int
	Password string
	IsAuthenticated bool
	IsTls bool
	DebounceNS int64
}

func (c *SMTPClient) Connect(addr ...string) {
	var err error
	if (len(addr) > 0) {
		c.Conn, err = net.Dial("tcp", addr[0])
		if err != nil {
			fmt.Println(err)
		}
	} else {
		c.Conn, err = net.Dial("tcp", c.Host+":"+strconv.Itoa(c.Port))
		if err != nil {
			fmt.Println(err)
		}
	}
	response, err := bufio.NewReader(c.Conn).ReadString('\n')
	if err != nil {
		fmt.Println(err)
	}
	fmt.Print(response)
}

func (c* SMTPClient) Helo(name ...string) {
	if (len(name) > 0) {
		fmt.Fprintf(c.Conn, "HELO "+name[0]+"\r\n")
	} else {
		fqdn, err := os.Hostname()
		if err != nil {
			fmt.Println(err)
		}
		fmt.Fprintf(c.Conn, "HELO "+fqdn+"\r\n")
	}
	response, err := bufio.NewReader(c.Conn).ReadString('\n')
	if err != nil {
		fmt.Println(err)
	}
	fmt.Print(response)
}

func (c* SMTPClient) Ehlo(name ...string) {
	if (len(name) > 0) {
		fmt.Fprintf(c.Conn, "EHLO "+name[0]+"\r\n")
	} else {
		fqdn, err := os.Hostname()
		if err != nil {
			fmt.Println(err)
		}
		fmt.Fprintf(c.Conn, "EHLO "+fqdn+"\r\n")
	}
	for {
		response, err := bufio.NewReader(c.Conn).ReadString('\n')
		if err != nil {
			fmt.Println(err)
		}
		fmt.Print(response)
		if (strings.HasPrefix(response, "250 ")) {
			break
		}
	}
}

func (c *SMTPClient) Auth(method string) {
	method = strings.ToUpper(method)
	fmt.Fprintf(c.Conn, "AUTH "+method+"\r\n")
	response, err := bufio.NewReader(c.Conn).ReadString('\n')
	if err != nil {
		fmt.Println(err)
	}
	fmt.Print(response)
	if (!strings.HasPrefix(response, "334")) {
		return
	}
	if (method == "PLAIN") {
		credentials := base64.StdEncoding.EncodeToString([]byte(c.Password))
		fmt.Fprintf(c.Conn, credentials+"\r\n")
		response, err := bufio.NewReader(c.Conn).ReadString('\n')
		if err != nil {
			fmt.Println(err)
		}
		fmt.Print(response)
		if (strings.HasPrefix(response, "235")) {
			c.IsAuthenticated = true
		}
		return
	}
	if (method == "DIGEST-MD5") {
		hash := md5.Sum([]byte(c.Password))
		credentials := base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(hash[:])))
		fmt.Fprintf(c.Conn, credentials+"\r\n")
		response, err := bufio.NewReader(c.Conn).ReadString('\n')
		if err != nil {
			fmt.Println(err)
		}
		fmt.Print(response)
		if (strings.HasPrefix(response, "235")) {
			c.IsAuthenticated = true
		}
		return
	}
	if (method == "CRAM-MD5") {
		challenge := strings.Trim(response[len("334 "):], "\r\n")
		secretHash := md5.New()
		secretHash.Write([]byte(c.Password))
		key := secretHash.Sum(nil)

		sig := hmac.New(md5.New, key)
		sig.Write([]byte(challenge))
		credentials := base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(sig.Sum(nil))))
		fmt.Fprintf(c.Conn, credentials+"\r\n")
		response, err := bufio.NewReader(c.Conn).ReadString('\n')
		if err != nil {
			fmt.Println(err)
		}
		fmt.Print(response)
		if (strings.HasPrefix(response, "235")) {
			c.IsAuthenticated = true
		}
		return
	}
	if (method == "DIGEST-SHA256") {
		h := sha256.New()
		h.Write([]byte(c.Password))

		credentials := base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(h.Sum(nil))))

		fmt.Fprintf(c.Conn, credentials+"\r\n")
		response, err := bufio.NewReader(c.Conn).ReadString('\n')
		if err != nil {
			fmt.Println(err)
		}
		fmt.Print(response)
		if (strings.HasPrefix(response, "235")) {
			c.IsAuthenticated = true
		}
		return
	}
	if (method == "CRAM-SHA256") {
		challenge := strings.Trim(response[len("334 "):], "\r\n")

		secretHash := md5.New()
		secretHash.Write([]byte(c.Password))
		key := secretHash.Sum(nil)

		sig := hmac.New(sha256.New, key)
		sig.Write([]byte(challenge))

		credentials := base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(sig.Sum(nil))))
		fmt.Fprintf(c.Conn, credentials+"\r\n")
		response, err := bufio.NewReader(c.Conn).ReadString('\n')
		if err != nil {
			fmt.Println(err)
		}
		fmt.Print(response)
		if (strings.HasPrefix(response, "235")) {
			c.IsAuthenticated = true
		}
		return
	}
}

func (c *SMTPClient) StartTls() {
	fmt.Fprintf(c.Conn, "STARTTLS\r\n")
	response, err := bufio.NewReader(c.Conn).ReadString('\n')
	if err != nil {
		fmt.Println(err)
	}
	fmt.Print(response)
	c.IsTls = true
}

func (c *SMTPClient) Send(email Email) {
	sender := email.SenderAddr
	recipients := email.Recipients
	data := email.ToString()
	fmt.Fprintf(c.Conn, "MAIL FROM:<"+sender+">\r\n")
	response, err := bufio.NewReader(c.Conn).ReadString('\n')
	if err != nil {
		fmt.Println(err)
	}
	fmt.Print(response)
	if (!strings.HasPrefix(response, "250")) {
		return
	}
	for _, recipient := range recipients {
		fmt.Fprintf(c.Conn, "RCPT TO:<"+recipient["address"]+">\r\n")
		response, err = bufio.NewReader(c.Conn).ReadString('\n')
		if err != nil {
			fmt.Println(err)
		}
		fmt.Print(response)
		if (!strings.HasPrefix(response, "250")) {
			return
		}
	}
	fmt.Fprintf(c.Conn, "DATA \r\n")
	response, err = bufio.NewReader(c.Conn).ReadString('\n')
	if err != nil {
		fmt.Println(err)
	}
	fmt.Print(response)
	if (!strings.HasPrefix(response, "354")) {
		return
	}
	for _, line := range strings.Split(data, "\r\n") {
		fmt.Fprintf(c.Conn, line+"\r\n")
		debounce(c.DebounceNS)
	}
	
	response, err = bufio.NewReader(c.Conn).ReadString('\n')
	if err != nil {
		fmt.Println(err)
	}
	fmt.Print(response)
}

func (c *SMTPClient) MaxSize() {
	fmt.Fprintf(c.Conn, "SIZE\r\n")
	response, err := bufio.NewReader(c.Conn).ReadString('\n')
	if err != nil {
		fmt.Println(err)
	}
	fmt.Print(response)
}

func (c *SMTPClient) Help() {
	fmt.Fprintf(c.Conn, "HELP\r\n")
	response, err := bufio.NewReader(c.Conn).ReadString('\n')
	if err != nil {
		fmt.Println(err)
	}
	fmt.Print(response)
}

func (c *SMTPClient) Reset() {
	fmt.Fprintf(c.Conn, "RSET\r\n")
	response, err := bufio.NewReader(c.Conn).ReadString('\n')
	if err != nil {
		fmt.Println(err)
	}
	fmt.Print(response)
}

func (c *SMTPClient) Quit() {
	fmt.Fprintf(c.Conn, "QUIT\r\n")
	response, err := bufio.NewReader(c.Conn).ReadString('\n')
	if err != nil {
		fmt.Println(err)
	}
	fmt.Print(response)
}

func debounce(duration int64) {
	start := time.Now().UnixNano()
    for {
		if (time.Now().UnixNano() - start > duration) {
			break
		}
	}
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	port, _ := strconv.Atoi(os.Getenv("SMTP_PORT"))
	client := SMTPClient{
		Host: os.Getenv("SMTP_HOST"), 
		Port: port, 
		Password: os.Getenv("SMTP_PASS"),
		DebounceNS: 500_000,
	}
	
	client.Connect()
	client.Ehlo()
	client.Auth("CRAM-MD5")
	
	message := "Hello Alice.\r\n"
	message += "This is a test message with 5 header fields and 4 lines in the message body.\r\n"
	message += "Your friend,\r\n"
	message += "Bob"
	email := Email{
		SenderName: "Bob",
		SenderAddr: "bob@email.com",
		Subject: "This is a test",
		Message: message,
	}
	email.AddRecipient("Alice", "alice@email.com")
	client.Send(email)
	
	client.Quit()
}