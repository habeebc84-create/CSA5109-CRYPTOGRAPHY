text = input("Enter text: ")
key = int(input("Enter key: "))

result = ""

for ch in text:
    if ch.isalpha():
        result += chr((ord(ch) - 65 + key) % 26 + 65)

print("Encrypted Text:", result)
