from flask import Flask, request
from flask_restful import Resource, Api

app = Flask(__name__)
api = Api(app)


class BookModel:
    _pk = 1
    def __init__(self, title, author):
        self.pk = BookModel._pk
        self.title = title
        self.author = author
        BookModel._pk += 1

    def serialize(self):
        return self.__dict__

    def __str__(self):
        return f"{self.pk} Title: {self.title} from {self.author}"


books = [BookModel(f"Title {i}", f"Author {i}") for i in range(1, 11)]


class Books(Resource):
    def get(self):
        return [book.__dict__ for book in books]

    def post(self):
        data = request.get_json()
        book = BookModel(title=data.get("title"), author=data.get("author"))
        books.append(book)
        return [book.__dict__ for book in books]


class Book(Resource):
    def _get_book(self, pk):
        try:
            return [b for b in books if b.pk == pk][0]
        except IndexError:
            return None

    def get(self, pk):
        book = self._get_book(pk)
        if not book:
            return "Book does not exist."
        return book.__dict__


    def put(self, pk):
        book = self._get_book(pk)
        if not book:
            return "Book does not exist."
        data = request.get_json()
        book.title = data.get("title")
        book.author = data.get("author")
        return book.__dict__


    def delete(self, pk):
        book = self._get_book(pk)
        if not book:
            return "Book does not exist."
        books.remove(book)



api.add_resource(Books, "/books/")
api.add_resource(Book, "/books/<int:pk>")


if __name__ == "__main__":
    print([book.__dict__ for book in books])
    app.run(debug=True)