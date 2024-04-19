import http.server
import os
import socketserver

PORT = 8000
ALLOWED_DIRS = ["deployment_data", "deployments"]  # Directories allowed for access


class Handler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        # Call the superclass method to get the filesystem path
        fs_path = super().translate_path(path)

        # Get the base directory of the requested path
        base_dir = os.path.relpath(fs_path, os.getcwd()).split(os.sep)[0]

        # Check if the base directory is in the list of allowed directories
        if base_dir in ALLOWED_DIRS:
            return fs_path
        else:
            # If the directory is not allowed, raise a 404 error
            self.send_error(404, "File not found")
            return None


def main():
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"Serving at http://localhost:{PORT}")
        httpd.serve_forever()


if __name__ == '__main__':
    main()
