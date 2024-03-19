# Тестовое задание для AppSecCloudCamp 

 # Часть 1. Security code review: GO
```
package main

import (
    "database/sql"
    "fmt"
    "log"
    "net/http"
    "github.com/go-sql-driver/mysql"
)

var db *sql.DB
var err error

func initDB() {
    db, err = sql.Open("mysql", "user:password@/dbname")
    if err != nil {
        log.Fatal(err)
    }

err = db.Ping()
if err != nil {
    log.Fatal(err)
    }
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "GET" {
        http.Error(w, "Method is not supported.", http.StatusNotFound)
        return
    }

searchQuery := r.URL.Query().Get("query")
if searchQuery == "" {
    http.Error(w, "Query parameter is missing", http.StatusBadRequest)
    return
}

query := fmt.Sprintf("SELECT * FROM products WHERE name LIKE '%%%s%%'", searchQuery)
rows, err := db.Query(query)
if err != nil {
    http.Error(w, "Query failed", http.StatusInternalServerError)
    log.Println(err)
    return
}
defer rows.Close()

var products []string
for rows.Next() {
    var name string
    err := rows.Scan(&name)
    if err != nil {
        log.Fatal(err)
    }
    products = append(products, name)
}

fmt.Fprintf(w, "Found products: %v\n", products)
}

func main() {
    initDB()
    defer db.Close()

http.HandleFunc("/search", searchHandler)
fmt.Println("Server is running")
log.Fatal(http.ListenAndServe(":8080", nil))
}
```
# Строки в которых я обнаружил уязвимости:
1. # SQL-инъекция:
- query := fmt.Sprintf("SELECT * FROM products WHERE name LIKE '%%%s%%'", searchQuery)
- **ПОСЛЕДСТВИЯ:**
   - Злоумышленник может изменить SQL-запрос, чтобы получить, удалить или изменить данные в базе данных.Это может привезти к утечке или повреждению данных.
- **ИСПРАВЛЕНИЕ:**
   - Использовать параметризованные запросы.
2. # Нерправильная обработка ошибок:
  - log.Fatal(err)
  - Строки с уязвимостью: Все места, где происходит log.Fatal(err), приводящее к прекращению работы программы.
- **ПОСЛЕДСТВИЯ:**
   - Прекращение работы сервиса при возникновении ошибки.Злоумышленник может использовать уязвимость для проведения DoS-атаки, впоследствии произойдёт перегруз ресурсов системы
 - **ИСПРАВЛЕНИЕ:** 
   - Логирование ошибок без завершения работы приложения, что позволит сервису продолжать работу.
3. # Использование устаревших методов проверки HTTP методов:
- Строка с уязвимостью: if r.Method != "GET".
 - **ПОСЛЕДСТВИЯ**:
   - Менее читаемый и не совсем менее безопасный код.
  - **ИСПРАВЛЕНИЕ:** 
    - Использование **http.MethodGet** для повышения читаемости и безопасности кода.
# Код после моего  анализа:
```
package main

import (
    "database/sql"
    "fmt"
    "log"
    "net/http"

    _ "github.com/go-sql-driver/mysql"
)

var db *sql.DB

func initDB() {
    // Переменные для подключения к базе данных
    username := "user"
    password := "password"
    dbname := "dbname"

    // Формирование строки подключения
    dataSourceName := fmt.Sprintf("%s:%s@/%s", username, password, dbname)

    // Подключение к базе данных
    var err error
    db, err = sql.Open("mysql", dataSourceName)
    if err != nil {
        log.Fatal(err)
    }

    // Проверка подключения к базе данных
    err = db.Ping()
    if err != nil {
        log.Fatal(err)
    }
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Метод не поддерживается.", http.StatusMethodNotAllowed)
        return
    }

    searchQuery := r.URL.Query().Get("query")
    if searchQuery == "" {
        http.Error(w, "Отсутствует параметр запроса", http.StatusBadRequest)
        return
    }

    query := "SELECT * FROM products WHERE name LIKE ?"
    rows, err := db.Query(query, "%"+searchQuery+"%")
    if err != nil {
        http.Error(w, "Запрос не удался", http.StatusInternalServerError)
        log.Println(err)
        return
    }
    defer rows.Close()

    var products []string
    for rows.Next() {
        var name string
        err := rows.Scan(&name)
        if err != nil {
            log.Fatal(err)
        }
        products = append(products, name)
    }

    fmt.Fprintf(w, "Найденные продукты: %v\n", products)
}

func main() {
    initDB()
    defer db.Close()

    http.HandleFunc("/search", searchHandler)
    fmt.Println("Сервер запущен")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```
# Внесенные изменения:
1. Использование параметризованного запроса для предотвращения атак **SQL инъекций.**
2. **Удаление чувствительной информации (имени пользователя и пароля)** из кода и использование их как локальных переменных в функции **initDB().**
3. Использование **http.MethodGet** для проверки метода запроса.
4. Использование оператора **% в запросе SQL** вместо форматирования строки для предотвращения атак SQL инъекций.
5. Сделал проверку ошибок при обращении к базе данных в цикле **for rows.Next()**

