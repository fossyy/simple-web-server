run: generate tailwindcss
	@go run main.go

generate:
	@templ generate

tailwindcss:
	@npx tailwindcss -i ./public/input.css -o ./public/output.css