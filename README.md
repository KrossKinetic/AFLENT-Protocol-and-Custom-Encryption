# CSE 220 HW2: AFLENT Protocol and Custom Encryption

This project, completed for CSE 220: Systems Fundamentals I at Stony Brook University, focuses on low-level data manipulation in C. It involves implementing a custom network protocol, named **AFLENT**, and a block cipher for data encryption and decryption. The core of the project is performing byte and bit-level computations to pack, unpack, and transform data.

---

## 💡 Learning Outcomes

This project demonstrates proficiency in:
* Performing byte-level computations.
* Using bit-level operations (AND, OR, XOR, shifts) for computation.
* Traversing and manipulating byte arrays.

---

## 📦 Part 1: Parsing AFLENT Packets

This part involved creating a parser for the AFLENT protocol. The goal was to take a raw byte array representing a packet and extract its header fields and payload.

The `print_packet` function was implemented to read a packet and print its contents in a structured format.

### AFLENT Packet Structure

An AFLENT packet consists of a 3-byte header followed by a variable-length payload.

| Byte | Bit 7-2 | Bit 1-0 |
| :--- | :--- | :--- |
| `char[0]` | `Array Number` | `Frag[4:3]` |
| **Byte** | **Bit 7-5** | **Bit 4-0** |
| `char[1]` | `Frag[2:0]` | `Length[9:5]`|
| **Byte** | **Bit 7-3** | **Bit 2-0** |
| `char[2]` | `Length[4:0]` | `Encrypt` `Endian` `Last` |
| `char[3+]`| `Payload` | |

**Header Fields:**
* **Array Number (6 bits):** Identifies which of the 64 possible arrays the data belongs to.
* **Fragment Number (5 bits):** Specifies the packet's sequence number within an array.
* **Length (10 bits):** The number of 32-bit integers in the payload.
* **Encrypt (1 bit):** A flag indicating if the payload is encrypted (1) or plaintext (0).
* **Endian (1 bit):** A flag indicating if the payload is Little-Endian (1) or Big-Endian (0).
* **Last (1 bit):** A flag indicating if this is the final fragment for a given array.

---

## 🛠️ Part 2: Building AFLENT Packets

This section involved implementing the `build_packets` function, which takes an array of integers and constructs a sequence of AFLENT packets.

**Key functionality includes:**
* **Packet Construction:** Assembling the 3-byte header by correctly placing the **Array Number**, **Fragment Number**, **Length**, and flags using bitwise operations.
* **Fragmentation:** If the data's byte length (`data_length * 4`) exceeds the `max_fragment_size`, the function splits the data across multiple packets, correctly setting the fragment number and `Last` flag for each.
* **Endianness Handling:** Reversing the byte order for each 32-bit integer in the payload if the `endianness` flag is set to 1 (Little-Endian).
* **Dynamic Memory Allocation:** Allocating sufficient memory on the heap to store the complete byte stream of all generated packets.

---

## 🧩 Part 3: Assembling Arrays from Packets

The `create_arrays` function was developed to perform the reverse operation: reassembling complete integer arrays from a stream of incoming AFLENT packets.

**This task required handling several complexities:**
* **Out-of-Order Packets:** Packets could arrive out of order, requiring a mechanism to place payload data in the correct position based on the **Array Number** and **Fragment Number**.
* **Multiple Arrays:** The input stream could contain packets for multiple different arrays (`array_count`), which needed to be separated and reassembled independently.
* **Dynamic Sizing:** Memory for each final array was allocated dynamically, potentially using `realloc` as new fragments arrived and the total required size became clear.
* **Endian Conversion:** The payload bytes were converted back into 32-bit integers, respecting the `Endian` flag in each packet's header.

---

## 🔒 Part 4: Custom Encryption & Decryption

The final part was to implement a custom symmetric block cipher. This involved writing the `sbu_encrypt` and `sbu_decrypt` functions based on provided pseudocode.

### Core Operations

The algorithm is built upon several low-level bit and byte manipulation functions:
* **Key Expansion:** A `sbu_expand_keys` function takes a 64-bit key and expands it into a 1024-bit key schedule used for the encryption and decryption rounds.
* **Bitwise Functions:**
    * `Rotate Left/Right`: Circularly shifts the bits of a number.
    * `Reverse`: Reverses the bit order of a 32-bit integer (e.g., bit 31 swaps with bit 0).
    * `Shuffle/Unshuffle`: Interleaves or de-interleaves the bits of a 32-bit value in 1-bit or 4-bit chunks.
* **Round Functions:** The core `encrypt` and `decrypt` functions apply a series of `scramble` and `mash` operations over multiple rounds. These operations use XOR, AND, NOT, and the bitwise functions above to thoroughly mix the input data with the expanded key.
* **Symmetry:** The `decrypt` function is the mirror inverse of the `encrypt` function, applying the reverse of each operation in the opposite order to restore the original plaintext.

---

## 🚀 How to Build and Run

The project uses CMake for building.

1.  **Configure the build (run once):**
    ```bash
    cmake -S . -B build
    ```

2.  **Build the code:**
    ```bash
    cmake --build build
    ```

3.  **Run Tests:**
    Execute the test runner targets to test each part of the assignment:
    ```bash
    ./build/partl
    ./build/part2
    ./build/part3
    ./build/part_4_tests
    ```

---

## CSE220 Completion Score: 100%, Class Average Score of HW 1-4: 60%-70%
