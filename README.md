# Library API Documentation

Welcome to the Library API! This API provides a powerful and secure solution for managing library resources, including users, authors, and books. Designed for ease of use and scalability, it enables seamless integration of library management capabilities into various applications. Whether you're building a library management system, a book cataloging platform, or any application that requires robust CRUD functionality, this API has you covered.

Each endpoint is equipped with built-in security features to ensure safe and reliable operations. The API supports features such as user registration, authentication, and authorization to protect resources. It also facilitates the management of books, authors, and their relationships, enabling advanced data organization and querying

---

##### User REGISTRATION
**URL: POST /user/register**
**Method: POST**

### Payload
```bash
{
  "username": "username",
  "password": "password"
}
```
### Response
```bash
{
  "status": "success",
  "token": null,
  "data": null
}
```

##### User Authentication
**URL: POST /user/auth**
**Method: POST**

### Payload
```bash
{
  "username": "username",
  "password": "password"
}
```
### Response
```bash
{
  "status": "success",
  "token": "token from authentication",
  "data": null
}
```

## Author Endpoints
**Register Author**
**URL: POST /author/register**
**Method: POST**

### Payload
```bash
{
  "username": "your_username",
  "password": "your_password"
}

```
### Response
```bash
{
  "status": "success",
  "message": "Author registered successfully."
}
```

### Update Author
**URL:`POST /author/post`** 
**Method:`POST`** 

#### Payload  
```
{
  "token": "token from authentication",
  "author": "NEW_AUTHOR"
}
```
#### Response
```
{
  "status": "success",
  "message": "updated successfully."
}
```

### Get AUTHOR
**URL:`Get /author/get`**
**Method:`GET`** 

#### Payload  
```
{
  "token": "token from authentication"
}
```
#### Response
```
{
  "status": "success",
  "data": [
    {
      "author_id": "author_15",
      "name": "Author Name",
      "books": [
        "Book 1",
        "Book 2"
      ]
    }
  ]
}

```

### Delete AUTHOR
URL: `DELETE /author/delete{id}
Method: `DELETE`

#### Payload  
```
{
  "token": " token from authentication"
}
```
#### Response
```
{
  "status": "success",
  "message": "Author deleted successfully."
}

```
## Books Endpoints
**Get BOOKS**
**URL: Get /book/get**
**Method: `GET`**  

#### Payload  
```
{
  "token": "token from authentication"
}
```
#### Response
```
{
  "status": "success",
  "data": [
    {
      "book_id": "100",
      "title": "Title_of_Book",
      "author_id": "author_15"
    }
  ]
}

```

### Update Book
**URL: PUT /book/update{id}**
**Method: `PUT`**

#### Payload  
```
{
"book_id": 100,
"token": "token_from_authentication",
"title": "New_Book_Title"
}
```
#### Response
```
{
  "status": "success",
  "message": "Book updated successfully."
}
```
### Delete Book
**URL: DELETE /book/delete{id}**
**Method: `DELETE`**

#### Payload  
```
{
  "book_id": 35,
  "token": "token_from_authentication"
}

```
#### Response
```
{
  "status": "success",
  "message": "Book deleted successfully."
}

```

### Get All Book-Author Relations
**URL: Get /book/author/get**
**Method: `GET`**


#### Payload  
```
{
  "authorid": author_20,
  "bookid": 40,
  "token": "token from authentication"
}


```
#### Response
```
{
  "status": "success",
  "data": [
    {
      "relation_id": "11",
      "book_id": "7",
      "author_id": "author_30"
    }
  ]
}

```

## CREATED BY:
**Rolielyn B. Florendo/ BS INFOTECH 4C**


















