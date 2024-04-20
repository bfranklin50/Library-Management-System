import tkinter as tk
from PIL import Image, ImageTk
from tkinter import ttk, messagebox
import mysql.connector
import hashlib

class Database:
    """Handles database operations."""

    def __init__(self, host, user, password, database):
        """Initialize the Database object.

        Args:
            host (str): Hostname or IP address of the database server.
            user (str): Username for accessing the database.
            password (str): Password for accessing the database.
            database (str): Name of the database to connect to.
        """


        self.connection = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            database=database
        )
    def execute_query(self, query, values=None):
        """Execute a database query.

                Args:
                    query (str): SQL query to execute.
                    values (tuple, optional): Values to substitute in the query placeholders.

                Returns:
                    list: List of dictionaries representing query results.
                """

        cursor = self.connection.cursor(dictionary=True)
        cursor.execute(query, values)
        result = cursor.fetchall()
        cursor.close()
        return result

    def execute_update(self, query, values=None):
        """Execute a database update operation.

                Args:
                    query (str): SQL query to execute.
                    values (tuple, optional): Values to substitute in the query placeholders.
                """

        cursor = self.connection.cursor()
        cursor.execute(query, values)
        self.connection.commit()
        cursor.close()

    def close(self):
        """Close the database connection."""
        self.connection.close()


class User:
    """Handles user operations."""

    def __init__(self, db):
        """Initialize the User object.

                Args:
                    db (Database): Database object for user-related operations.
                """
        self.db = db

    def hash_password(self, password):
        """Hash a password using SHA-256 algorithm.

               Args:
                   password (str): Password to hash.

               Returns:
                   str: Hashed password.
               """

        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        return hashed_password

    def login(self, username, password):
        """Authenticate user login.

                Args:
                    username (str): User's username.
                    password (str): User's password.

                Returns:
                    dict or None: User information if login is successful, None otherwise.
                """

        query = "SELECT user_id, user_type, first_name, last_name, username, hashed_password FROM user_table WHERE username = %s"
        values = (username,)
        result = self.db.execute_query(query, values)

        print(f"Query result: {result}")

        if result:
            stored_hashed_password = result[0]['hashed_password']
            entered_password_hash = self.hash_password(password)

            #print(f"Stored Hashed Password: {stored_hashed_password}")
            #print(f"Entered Password Hash: {entered_password_hash}")

            if stored_hashed_password == entered_password_hash:
                return result[0]
            else:
                return None
        else:
            return None

    def create_user(self, user_type, first_name, last_name, username, password, email):
        """Create a new user.

                Args:
                    user_type (str): Type of the user ('admin' or 'borrower').
                    first_name (str): First name of the user.
                    last_name (str): Last name of the user.
                    username (str): Username for the new user.
                    password (str): Password for the new user.
                    email (str): Email address of the new user.

                Returns:
                    str: Message indicating the success or failure of user registration.
                """

        hashed_password = self.hash_password(password)
        query = "INSERT INTO user_table (user_type, first_name, last_name, username, hashed_password, email, join_date) VALUES (%s, %s, %s, %s, %s, %s, NOW())"
        values = (user_type, first_name, last_name, username, hashed_password, email)

        try:
            self.db.execute_update(query, values)
            return f"{user_type} user has been registered!"
        except mysql.connector.Error as err:
            return f"Error: {err}"


class Book:
    """Handles book operations."""

    def __init__(self, db):
        """Initialize the Book object.

                Args:
                    db (Database): Database object for book-related operations.
                """

        self.db = db

    def insert_book(self, title, authors, publication_date, isbn13, publisher, average_rating, language_code, num_pages,
                    ratings_count, text_reviews_count):
        """Insert a new book into the database.

                Args:
                    title (str): Title of the book.
                    authors (str): Authors of the book.
                    publication_date (str): Publication date of the book.
                    isbn13 (str): ISBN-13 code of the book.
                    publisher (str): Publisher of the book.
                    average_rating (float): Average rating of the book.
                    language_code (str): Language code of the book.
                    num_pages (int): Number of pages in the book.
                    ratings_count (int): Number of ratings for the book.
                    text_reviews_count (int): Number of text reviews for the book.

                Returns:
                    str: Message indicating the success or failure of book insertion.
                """

        query = "INSERT INTO book_table (title, authors, publication_date, isbn13, publisher, average_rating, language_code, num_pages, ratings_count, text_reviews_count, total_copies, available_copies) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 1, 1)"
        values = (
        title, authors, publication_date, isbn13, publisher, average_rating, language_code, num_pages, ratings_count,
        text_reviews_count)

        try:
            self.db.execute_update(query, values)
            return "Book has been added!"
        except mysql.connector.Error as err:
            return f"Error: {err}"

    def select_books(self):
        """Select all books from the database.

                Returns:
                    list: List of dictionaries representing book information.
                """

        query = "SELECT * FROM book_table ORDER BY title"
        result = self.db.execute_query(query)
        return result

    def delete_book(self, isbn13_to_delete):
        """Delete a book from the database.

                Args:
                    isbn13_to_delete (str): ISBN-13 code of the book to delete.

                Returns:
                    str: Message indicating the success or failure of book deletion.
                """

        query = "DELETE FROM book_table WHERE isbn13 = %s"
        values = (isbn13_to_delete,)
        self.db.execute_update(query, values)
        return "Book has been deleted"

    def update_book(self, isbn13_to_update, new_title, new_authors, new_publication_date):
        """Update book information in the database.

                Args:
                    isbn13_to_update (str): ISBN-13 code of the book to update.
                    new_title (str): New title for the book.
                    new_authors (str): New authors for the book.
                    new_publication_date (str): New publication date for the book.

                Returns:
                    str: Message indicating the success or failure of book update.
                """

        query = "UPDATE book_table SET title=%s, authors=%s, publication_date=%s WHERE isbn13=%s"
        values = (new_title, new_authors, new_publication_date, isbn13_to_update)
        self.db.execute_update(query, values)
        return "Book has been updated"


class LibraryApp:
    """Main application window."""

    def __init__(self):
        """Initialize the LibraryApp object.

        rgs:
            db (Database): Database object for application operations.
        """

        self.db = Database(host="3.93.47.117", user="bfranklin", password="123456", database="LibrarySystem")
        self.user_manager = User(self.db)
        self.book_manager = Book(self.db)
        self.book_info_entries = {}  # Dictionary to store label text and corresponding entry widget

    def login_window(self):
        """Display login window."""

        login_window = tk.Tk()
        login_window.title("Login")

        # Load the background image
        background_image = Image.open("images/backgroundimage.jpg")  # Replace with the actual image file
        background_photo = ImageTk.PhotoImage(background_image)

        # Create a Label with the background image
        background_label = tk.Label(login_window, image=background_photo)
        background_label.place(relwidth=1, relheight=1)

        login_window.geometry("600x500")
        label_font = ("Arial", 14)  # Example font: Arial, size 14
        entry_font = ("Arial", 12)  # Example font: Arial, size 12
        self.button_font = ("Arial", 14, "bold")  # Example font: Arial, size 14, bold

        # Configure columns to center content
        login_window.columnconfigure(0, weight=1)
        login_window.columnconfigure(1, weight=1)

        # Configure rows to center content
        for i in range(7):
            login_window.rowconfigure(i, weight=1)

        tk.Label(login_window, text="Welcome to The Bridgehampton Community Center Library", font=("Arial", 16, "bold")).grid(row=0,
                                                                                                         column=0,
                                                                                                         columnspan=2,
                                                                                                         pady=(20, 10),                                                                                     sticky="n")

        tk.Label(login_window, text="Username:", font=label_font).grid(row=2, column=0, pady=(5, 0), sticky="e")
        username_entry = tk.Entry(login_window, font=entry_font)
        username_entry.grid(row=2, column=1, pady=(8, 0), sticky="w")

        tk.Label(login_window, text="Password:", font=label_font).grid(row=3, column=0, pady=(5, 0), sticky="e")
        password_entry = tk.Entry(login_window, show="*", font=entry_font)
        password_entry.grid(row=3, column=1, pady=(8, 0), sticky="w")

        tk.Button(login_window, text="Login",
                  command=lambda: self.validate_login(username_entry.get(), password_entry.get(), login_window),
                  font=self.button_font).grid(row=4, column=0, columnspan=2, pady=(20, 10))

        login_window.bind('<Return>', lambda event=None: self.validate_login(username_entry.get(), password_entry.get(),
                                                                             login_window))

        login_window.mainloop()

    def validate_login(self, username, password, login_window):
        """Validate user login credentials.

                Args:
                    username (str): Username entered by the user.
                    password (str): Password entered by the user.
                    login_window: Tkinter window object for login window.
                """

        print(f"Attempting login with username: {username}, password: {password}")

        logged_in_user = self.user_manager.login(username, password)

        if logged_in_user:
            stored_hashed_password = logged_in_user['hashed_password']  # Change 'password' to 'hashed_password'
            entered_password_hash = self.user_manager.hash_password(password)

            if stored_hashed_password == entered_password_hash:
                #messagebox.showinfo("Login Successful", "Login successful!")
                login_window.destroy()
                self.options_window(logged_in_user)
            else:
                messagebox.showerror("Login Failed", "Invalid username or password. Please try again.")
                print(f"Login failed for username: {username}, password: {password}")
        else:
            messagebox.showerror("Login Failed", "Invalid username or password. Please try again.")
            print(f"Login failed for username: {username}, password: {password}")

    def register_user_window(self):
        """Display window for user registration."""

        register_window = tk.Tk()
        register_window.title("Register user")
        register_window.geometry("400x300")

        label_font = ("Arial", 14)
        entry_font = ("Arial", 12)
        button_font = ("Arial", 14, "bold")

        tk.Label(register_window, text="User Type (admin/borrower):", font=label_font).pack()
        user_type_entry = tk.Entry(register_window, font=entry_font)
        user_type_entry.pack()

        tk.Label(register_window, text="First Name:", font=label_font).pack()
        first_name_entry = tk.Entry(register_window, font=entry_font)
        first_name_entry.pack()

        tk.Label(register_window, text="Last Name:", font=label_font).pack()
        last_name_entry = tk.Entry(register_window, font=entry_font)
        last_name_entry.pack()

        tk.Label(register_window, text="Username:", font=label_font).pack()
        username_entry = tk.Entry(register_window, font=entry_font)
        username_entry.pack()

        tk.Label(register_window, text="Password:", font=label_font).pack()
        password_entry = tk.Entry(register_window, show="*", font=entry_font)
        password_entry.pack()

        tk.Label(register_window, text="Email:", font=label_font).pack()
        email_entry = tk.Entry(register_window, font=entry_font)
        email_entry.pack()

        tk.Button(register_window, text="Register",
                  command=lambda: self.validate_registration(user_type_entry.get(), first_name_entry.get(),
                                                             last_name_entry.get(), username_entry.get(),
                                                             password_entry.get(), email_entry.get(), register_window),
                  font=button_font).pack()

        register_window.mainloop()

    def validate_registration(self, user_type, first_name, last_name, username, password, email, register_window):
        """Validate user registration details."""

        print(f"Attempting registration with user type: {user_type}, username: {username}, password: {password}")

        # Validate user type (admin or borrower)
        if user_type.lower() not in ['admin', 'borrower']:
            messagebox.showerror("Registration Failed",
                                 "Invalid user type. Valid user types are 'admin' and 'borrower'.")
            print(f"Registration failed: Invalid user type - {user_type}")
            return

        result_message = self.user_manager.create_user(user_type, first_name, last_name, username, password, email)

        # Display the result message
        messagebox.showinfo("Registration", result_message)

        # Close the registration window after registration
        register_window.destroy()

    def options_window(self, logged_in_user):
        """Display options window."""

        options_window = tk.Tk()
        options_window.title("Options")

        options_window.geometry("500x400")

        label_font = ("Arial", 14)
        entry_font = ("Arial", 14)
        button_font = ("Arial", 14, "bold")

        tk.Button(options_window, text="Insert a book", command=self.insert_book_window, font=label_font).pack()
        tk.Button(options_window, text="List all books", command=self.select_all_books, font=label_font).pack()
        tk.Button(options_window, text="Delete a book", command=self.delete_book_window, font=label_font).pack()
        tk.Button(options_window, text="Update a book", command=self.update_book_window, font=label_font).pack()
        tk.Button(options_window, text="Register user", command=self.register_user_window, font=label_font).pack()
        tk.Button(options_window, text="Borrow a book", command=lambda: self.borrow_book_window(logged_in_user), font=label_font).pack()
        tk.Button(options_window, text="Return a book", command=self.return_book_window, font=label_font).pack()
        tk.Button(options_window, text="Books and Availability", command=self.book_availability_window, font=label_font).pack()
        tk.Button(options_window, text="Exit", command=options_window.destroy, font=label_font).pack()

    def insert_book_window(self):
        """Display window for inserting a book."""

        insert_book_window = tk.Tk()
        insert_book_window.title("Insert a Book")
        insert_book_window.geometry("500x600")

        label_font = ("Arial", 14)
        entry_font = ("Arial", 12)
        button_font = ("Arial", 14, "bold")

        # Labels and Entry widgets
        label_texts = ["Title:", "Authors:", "Publication Date:", "ISBN:", "Publisher:", "Average Rating:",
                       "Language Code:", "Number of Pages:", "Ratings Count:", "Text Reviews Count:"]

        for label_text in label_texts:
            label = tk.Label(insert_book_window, text=label_text, font=label_font)
            label.pack()

            entry = tk.Entry(insert_book_window, font=entry_font, width=40)
            entry.pack()

            # Store the label text and its corresponding entry widget in the dictionary
            self.book_info_entries[label_text] = entry

        tk.Button(insert_book_window, text="Insert Book", command=self.insert_book, font=self.button_font).pack()

        insert_book_window.mainloop()
    def insert_book(self):
        """Insert a book into the database."""

        title = self.book_info_entries["Title:"].get()
        authors = self.book_info_entries["Authors:"].get()
        publication_date = self.book_info_entries["Publication Date:"].get()
        isbn = self.book_info_entries["ISBN:"].get()
        publisher = self.book_info_entries["Publisher:"].get()
        average_rating = self.book_info_entries["Average Rating:"].get()
        language_code = self.book_info_entries["Language Code:"].get()
        num_pages = self.book_info_entries["Number of Pages:"].get()
        ratings_count = self.book_info_entries["Ratings Count:"].get()
        text_reviews_count = self.book_info_entries["Text Reviews Count:"].get()

        # Check if the ISBN already exists
        existing_book = self.db.execute_query("SELECT * FROM book_table WHERE isbn13 = %s", (isbn,))

        if existing_book:
            # ISBN already exists, update the copies
            total_copies = existing_book[0]['total_copies'] + 1
            available_copies = existing_book[0]['available_copies'] + 1

            # Update the existing book with the new total and available copies
            self.db.execute_update(
                "UPDATE book_table SET total_copies = %s, available_copies = %s WHERE isbn13 = %s",
                (total_copies, available_copies, isbn)
            )
            return f"Another copy of the book with ISBN {isbn} has been added."
        else:
            # Insert the new book
            query = "INSERT INTO book_table (title, authors, publication_date, isbn13, publisher, average_rating, language_code, num_pages, ratings_count, text_reviews_count, total_copies, available_copies) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 1, 1)"
            values = (
                title, authors, publication_date, isbn, publisher, average_rating, language_code, num_pages,
                ratings_count, text_reviews_count
            )

            try:
                self.db.execute_update(query, values)
                result_message = "Book has been added!"
            except mysql.connector.Error as err:
                result_message = f"Error: {err}"

            print("Book details:", title, authors, publication_date, isbn, publisher, average_rating,
                  language_code, num_pages, ratings_count, text_reviews_count)

        # Display the result message
        messagebox.showinfo("Insert Book", result_message)

        # Clear all entry fields for the next entry
        for entry in self.book_info_entries.values():
            entry.delete(0, tk.END)

    def select_all_books(self):
        """Display all books in a new window."""

        result = self.book_manager.select_books()

        books_window = tk.Toplevel()
        books_window.title("All Books")

        text_widget = tk.Text(books_window, width=120, height=50, font=("Arial", 12))
        text_widget.pack(padx=10, pady=10, side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(books_window, command=text_widget.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        text_widget.config(yscrollcommand=scrollbar.set)

        for book in result:
            title = book.get('title', 'N/A')
            authors = book.get('authors', 'N/A')
            isbn13 = book.get('ISBN13', 'N/A')

            text_widget.tag_configure('title', font=("Arial", 12, 'bold'))

            # Insert book information with bold title
            text_widget.insert(tk.END, f"{title}\n", 'title')
            text_widget.insert(tk.END, f"Authors: {authors}\nISBN13: {isbn13}\n")
            text_widget.insert(tk.END, "-" * 120 + "\n")  # Separator line

        # Disable editing after inserting content
        text_widget.config(state=tk.DISABLED)

        books_window.mainloop()

    def delete_book_window(self):
        """Display window for deleting a book."""

        delete_book_window = tk.Tk()
        delete_book_window.title("Delete a Book")
        delete_book_window.geometry("350x165")

        label_font = ("Arial", 14)
        entry_font = ("Arial", 12)
        button_font = ("Arial", 14, "bold")

        tk.Label(delete_book_window, text="ISBN13:", font=label_font).pack()
        isbn13_entry = tk.Entry(delete_book_window, font=entry_font)
        isbn13_entry.pack()

        tk.Button(delete_book_window, text="Delete a Book",
                  command=lambda: self.fetch_and_populate(isbn13_entry.get(), delete_book_window),
                  font=button_font).pack()


    def delete_book(self, isbn13_to_delete):
        """Delete a book from the database."""

        query = "DELETE FROM book_table WHERE isbn13 = %s"
        values = (isbn13_to_delete,)
        self.db.execute_update(query, values)
        return "Book has been deleted"

    def update_book_window(self):
        """Display window for updating a book."""

        update_book_window = tk.Tk()
        update_book_window.title("Update a Book")
        update_book_window.geometry("350x165")

        label_font = ("Arial", 14)
        entry_font = ("Arial", 12)
        button_font = ("Arial", 14, "bold")

        tk.Label(update_book_window, text="ISBN13:", font=label_font).pack()
        isbn13_entry = tk.Entry(update_book_window, font=entry_font)
        isbn13_entry.pack()

        tk.Button(update_book_window, text="Fetch Book",
                  command=lambda: self.fetch_and_populate(isbn13_entry.get(), update_book_window),
                  font=button_font).pack()

    def fetch_and_populate(self, isbn13, update_book_window):
        """Fetch book details and populate update fields."""

        existing_values = self.db.execute_query("SELECT * FROM book_table WHERE isbn13 = %s", (isbn13,))

        if existing_values:
            update_book_window.destroy()
            self.populate_update_fields(isbn13, existing_values[0])
        else:
            messagebox.showerror("Error", f"Book with ISBN13 {isbn13} not found.")

    def populate_update_fields(self, isbn13, existing_values):
        """Populate fields in the update book window."""

        update_book_window = tk.Tk()
        update_book_window.title("Update a Book")
        update_book_window.geometry("500x400")

        label_font = ("Arial", 14)
        entry_font = ("Arial", 12)
        button_font = ("Arial", 14, "bold")

        tk.Label(update_book_window, text="ISBN13:", font=label_font).pack()
        isbn13_entry = tk.Entry(update_book_window, font=entry_font)
        isbn13_entry.pack()

        tk.Label(update_book_window, text="New Title:", font=label_font).pack()
        new_title_entry = tk.Entry(update_book_window, font=entry_font)
        new_title_entry.pack()

        tk.Label(update_book_window, text="New Authors:", font=label_font).pack()
        new_authors_entry = tk.Entry(update_book_window, font=entry_font)
        new_authors_entry.pack()

        tk.Label(update_book_window, text="New Publication Date:", font=label_font).pack()
        new_publication_date_entry = tk.Entry(update_book_window, font=entry_font)
        new_publication_date_entry.pack()

        # Fetch existing values from the database
        existing_values = self.db.execute_query("SELECT * FROM book_table WHERE isbn13 = %s", (isbn13,))

        # If the book with the given ISBN does not exist, return an error message
        if not existing_values:
            messagebox.showerror("Error", "Book with the provided ISBN does not exist.")
            update_book_window.destroy()
            return

        # Populate the entry fields with existing values
        isbn13_entry.insert(tk.END, isbn13)
        new_title_entry.insert(tk.END, existing_values[0]['title'])
        new_authors_entry.insert(tk.END, existing_values[0]['authors'])
        new_publication_date_entry.insert(tk.END, existing_values[0]['publication_date'])

        tk.Button(update_book_window, text="Update Book",
                  command=lambda: self.update_book(isbn13_entry.get(),
                                                   new_title_entry.get(),
                                                   new_authors_entry.get(),
                                                   new_publication_date_entry.get()),
                  font=button_font).pack()

        update_book_window.mainloop()

    def update_book(self, isbn13_to_update, new_title=None, new_authors=None, new_publication_date=None):
        """Update book details in the database."""

        # Fetch existing values from the database
        existing_values = self.db.execute_query("SELECT * FROM book_table WHERE isbn13 = %s", (isbn13_to_update,))

        # If the book with the given ISBN does not exist, return an error message
        if not existing_values:
            messagebox.showerror("Error", "Book with the provided ISBN does not exist.")
            return

        # Create a dictionary to store the new values or existing values if not provided
        update_values = {
            'title': new_title if new_title is not None else existing_values[0]['title'],
            'authors': new_authors if new_authors is not None else existing_values[0]['authors'],
            'publication_date': new_publication_date if new_publication_date is not None else existing_values[0][
                'publication_date']
        }

        # Build the SQL query and values list dynamically
        set_clauses = [f"{key}=%s" for key in update_values.keys()]
        set_clause = ", ".join(set_clauses)
        query = f"UPDATE book_table SET {set_clause} WHERE isbn13=%s"
        values = [update_values[key] for key in update_values.keys()] + [isbn13_to_update]

        self.db.execute_update(query, values)
        messagebox.showinfo("Update Book", "Book has been updated")

    def borrow_book_window(self, logged_in_user):
        """Display window for borrowing a book."""

        borrow_book_window = tk.Tk()
        borrow_book_window.title("Borrow a Book")
        borrow_book_window.geometry("350x165")

        label_font = ("Arial", 14)
        entry_font = ("Arial", 12)
        button_font = ("Arial", 14, "bold")

        tk.Label(borrow_book_window, text="ISBN13:", font=label_font).pack()
        isbn13_entry = tk.Entry(borrow_book_window, font=entry_font)
        isbn13_entry.pack()

        tk.Button(borrow_book_window, text="Borrow Book",
                  command=lambda: self.borrow_book(isbn13_entry.get(), logged_in_user),
                  font=button_font).pack()

        borrow_book_window.mainloop()

    def borrow_book(self, isbn13, logged_in_user):
        """Borrow a book."""

        # Check if the book exists
        existing_book = self.db.execute_query("SELECT * FROM book_table WHERE isbn13 = %s", (isbn13,))

        if existing_book:
            # Check if the book is available for borrowing
            available_copies = existing_book[0]['available_copies']

            if available_copies > 0:
                # Update the available copies in the database
                self.db.execute_update(
                    "UPDATE book_table SET available_copies = %s WHERE isbn13 = %s",
                    (available_copies - 1, isbn13)
                )

                # Perform additional actions related to the borrowing process
                # (e.g., record the borrowing transaction, update user's borrowing history, etc.)

                messagebox.showinfo("Borrow Book", "Book has been borrowed successfully!")
            else:
                messagebox.showerror("Borrow Book", "Sorry, the book is currently not available for borrowing.")
        else:
            messagebox.showerror("Borrow Book", f"Book with ISBN13 {isbn13} not found.")

    def return_book_window(self):
        """Display window for returning a book."""

        return_book_window = tk.Tk()
        return_book_window.title("Return a Book")
        return_book_window.geometry("350x165")

        label_font = ("Arial", 14)
        entry_font = ("Arial", 12)
        button_font = ("Arial", 14, "bold")

        tk.Label(return_book_window, text="ISBN13:", font=label_font).pack()
        isbn13_entry = tk.Entry(return_book_window, font=entry_font)
        isbn13_entry.pack()

        tk.Button(return_book_window, text="Return Book",
                  command=lambda: self.return_book(isbn13_entry.get()),
                  font=button_font).pack()

        return_book_window.mainloop()

    def return_book(self, isbn13):
        """Return a book."""

        # Check if the book exists
        existing_book = self.db.execute_query("SELECT * FROM book_table WHERE isbn13 = %s", (isbn13,))

        if existing_book:
            # Update the available copies in the database (increase by 1)
            available_copies = existing_book[0]['available_copies']
            total_copies = existing_book[0]['total_copies']

            if available_copies < total_copies:
                self.db.execute_update(
                    "UPDATE book_table SET available_copies = %s WHERE isbn13 = %s",
                    (available_copies + 1, isbn13)
                )

                # Perform additional actions related to the return process
                # (e.g., update user's borrowing history, etc.)

                messagebox.showinfo("Return Book", "Book has been returned successfully!")
            else:
                messagebox.showerror("Return Book", "Invalid return operation. All copies are already available.")
        else:
            messagebox.showerror("Return Book", f"Book with ISBN13 {isbn13} not found.")

    def book_availability_window(self):
        """Display window for book availability."""

        # Fetch book availability information from the database
        result = self.db.execute_query(
            "SELECT title, authors, isbn13, total_copies, available_copies FROM book_table ORDER BY title")

        # Create a new window to display book availability
        book_availability_window = tk.Toplevel()
        book_availability_window.title("Book Availability")

        # Create a Treeview widget
        tree = ttk.Treeview(book_availability_window,
                            columns=("Title", "Authors", "ISBN13", "Total Copies", "Available Copies"), show="headings")

        # Set the anchor option for the columns you want to center
        for col in ("ISBN13", "Total Copies", "Available Copies"):
            tree.heading(col, anchor="center")
            tree.column(col, anchor="center")

        # Define column headings
        tree.heading("Title", text="Title")
        tree.heading("Authors", text="Authors")
        tree.heading("ISBN13", text="ISBN13")
        tree.heading("Total Copies", text="Total Copies")
        tree.heading("Available Copies", text="Available Copies")

        # Add data to the Treeview
        for book in result:
            title = book.get('title', 'N/A')
            authors = book.get('authors', 'N/A')
            isbn13 = book.get('isbn13', 'N/A')
            total_copies = book.get('total_copies', 0)
            available_copies = book.get('available_copies', 0)

            # Insert item and add 'title' tag only for the "Title" column
            title_item = tree.insert("", tk.END, values=(title, authors, isbn13, total_copies, available_copies),
                                     tags=('title',))
            tree.set(title_item, column="Title", value=title)  # Ensure the title column is set correctly

        # Add the Treeview to the window
        tree.pack(padx=10, pady=10, side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Create a scrollbar for the Treeview
        scrollbar = tk.Scrollbar(book_availability_window, command=tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Configure the Treeview to use the scrollbar
        tree.config(yscrollcommand=scrollbar.set)

        # Configure the 'title' tag to make it bold
        tree.tag_configure('title', font=('Arial', 12, 'bold'))

        self.mainloop = book_availability_window.mainloop()


if __name__ == "__main__":
    app = LibraryApp()
    app.login_window()