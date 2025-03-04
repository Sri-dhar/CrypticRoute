#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include "aes256.hpp"

ByteArray readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Could not open input file: " + filename);
    }

    file.seekg(0, std::ios::end);
    ByteArray::size_type fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    ByteArray buffer(fileSize);
    file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
    file.close();

    return buffer;
}

void writeFile(const std::string& filename, const ByteArray& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Could not open output file: " + filename);
    }

    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();
}

void printUsage(const char* programName) {
    std::cerr << "Usage for encryption: " << programName << " -e <input_file> <output_file> <key>" << std::endl;
    std::cerr << "Usage for decryption: " << programName << " -d <input_file> <output_file> <key>" << std::endl;
}

int main(int argc, char* argv[]) {
    try {
        if (argc != 5) {
            printUsage(argv[0]);
            return 1;
        }

        std::string mode = argv[1];
        std::string inputFile = argv[2];
        std::string outputFile = argv[3];
        std::string keyStr = argv[4];

        ByteArray key(keyStr.begin(), keyStr.end());
        ByteArray inputData = readFile(inputFile);
        ByteArray outputData;

        if (mode == "-e") {
            Aes256::encrypt(key, inputData, outputData);
            std::cout << "Encryption completed successfully." << std::endl;
        }
        else if (mode == "-d") {
            Aes256::decrypt(key, inputData, outputData);
            std::cout << "Decryption completed successfully." << std::endl;
        }
        else {
            printUsage(argv[0]);
            return 1;
        }

        writeFile(outputFile, outputData);

        std::cout << "Input file size: " << inputData.size() << " bytes" << std::endl;
        std::cout << "Output file size: " << outputData.size() << " bytes" << std::endl;

        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}