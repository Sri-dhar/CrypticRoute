#!/bin/bash

# --- Create Key Files ---
echo "Creating 5 key files with random AES-256 keys (hex encoded)..."
for i in {1..5}
do
  # Generate 32 random bytes (256 bits) and hex encode them
  # tr -d '\n' removes the trailing newline character often added by openssl/hex dump tools
  openssl rand -hex 32 | tr -d '\n' > "key_${i}.txt"
  echo "Created key_${i}.txt"
done
echo "Key files created."
echo

# --- Create Input Files ---
echo "Creating 10 input files with increasing text size (1 to 91 bytes)..."
for i in {1..10}
do
  # Calculate the size for this file: 1, 11, 21, ..., 91
  # Formula: size = 1 + (i - 1) * 10
  size=$((1 + (i - 1) * 10))

  # Generate random printable characters
  # 1. Generate more random bytes than needed using base64 encoding (ensures mostly printable)
  # 2. Remove any potential newlines added by base64
  # 3. Use head -c to take exactly the desired number of bytes ($size)
  openssl rand -base64 128 | tr -d '\n' | head -c $size > "input_${i}.txt"

  # Verify byte count (optional, uncomment to see)
  # actual_size=$(wc -c < "input_${i}.txt")
  # echo "Created input_${i}.txt (requested: $size bytes, actual: $actual_size bytes)"

  echo "Created input_${i}.txt ($size bytes)"

done
echo "Input files created."
echo

# --- Verification (Optional) ---
echo "Verifying file creation..."
echo "--- Key Files ---"
ls -l key_*.txt
echo "--- Input Files ---"
ls -l input_*.txt
echo
echo "--- Content Snippets ---"
echo "Key 1 content:"
head -n 1 key_1.txt
echo "Input 1 content (1 byte):"
cat input_1.txt # Use cat for 1 byte file
echo
echo "Input 5 content (41 bytes):"
head -n 1 input_5.txt
echo
echo "Input 10 content (91 bytes):"
head -n 1 input_10.txt
echo

echo "Done."

# --- Cleanup (Optional) ---
# Uncomment the next line to automatically remove the files after verification
# rm key_*.txt input_*.txt; echo "Cleaned up generated files."