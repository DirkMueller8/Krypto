using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

public class Program
{
    public static void Main(string[] args)
    {
        while (true)
        {
            try
            {
                Console.WriteLine("Encryption Program");
                Console.WriteLine("1. Symmetrical Hill-Chiffre: Input of Plaintext and of the key matrix");
                Console.WriteLine("2. Symmetrical Hill-Chiffre: Generiere eine zufällige Schlüsselmatrix");
                Console.WriteLine("3. Quit");
                Console.WriteLine("4. Asymmetrical Encryption with RSA");
                Console.Write("Please choose and ption: ");
                string option = Console.ReadLine() ?? string.Empty;

                if (option == "3")
                {
                    Console.WriteLine("Programm beendet.");
                    break;
                }

                if (option == "1" || option == "2")
                {
                    string plaintext = string.Empty;
                    int[,] keyMatrix;
                    int matrixSize;

                    if (option == "1")
                    {
                        // Eingabe des zu verschlüsselnden Textes
                        Console.Write("Give the plaintext to be encrypted: ");
                        plaintext = Console.ReadLine() ?? string.Empty;

                        // Eingabe der Schlüsselmatrix
                        Console.Write("Give the dimension of the key matrix ein (e.g. 2 for 2x2, 3 for 3x3): ");
                        if (!int.TryParse(Console.ReadLine(), out matrixSize))
                        {
                            matrixSize = 3; // Standardwert
                        }

                        keyMatrix = new int[matrixSize, matrixSize];
                        Console.WriteLine($"Give the elements of the {matrixSize}x{matrixSize} key matrix row by row, where individual values are separated by an empty space:");
                        for (int i = 0; i < matrixSize; i++)
                        {
                            Console.Write($"Zeile {i + 1}: ");
                            string[] row = (Console.ReadLine() ?? string.Empty).Split(' ');
                            for (int j = 0; j < matrixSize; j++)
                            {
                                keyMatrix[i, j] = int.Parse(row[j]);
                            }
                        }
                    }
                    else
                    {
                        // Generiere eine zufällige Schlüsselmatrix
                        Console.Write("Give the dimension of the key matrix ein (e.g. 2 for 2x2, 3 for 3x3): ");
                        if (!int.TryParse(Console.ReadLine(), out matrixSize))
                        {
                            matrixSize = 3; // Standardwert
                        }

                        HillCipher tempCipher = new HillCipher(matrixSize);
                        keyMatrix = tempCipher.GetKeyMatrix();

                        Console.WriteLine("Create random key matrix:");
                        for (int i = 0; i < matrixSize; i++)
                        {
                            for (int j = 0; j < matrixSize; j++)
                            {
                                Console.Write(keyMatrix[i, j] + " ");
                            }
                            Console.WriteLine();
                        }

                        // Eingabe des zu verschlüsselnden Textes
                        Console.Write("Give the plaintext to be encrypted: ");
                        plaintext = Console.ReadLine() ?? string.Empty;
                    }

                    // Instanz des HillCipher erstellen
                    HillCipher cipher = new HillCipher(matrixSize, keyMatrix);

                    // Verschlüsselung
                    string encryptedText = cipher.Encrypt(plaintext);
                    Console.WriteLine($"Encrypted text: {encryptedText}");

                    // Entschlüsselung
                    string decryptedText = cipher.Decrypt(encryptedText);
                    Console.WriteLine($"Decrypted text: {decryptedText}");
                }
                else if (option == "4")
                {
                    // RSA-Verschlüsselung
                    Console.Write("Give the plaintext to be encrypted: ");
                    string plaintext = Console.ReadLine() ?? string.Empty;

                    using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
                    {
                        try
                        {
                            // Öffentlichen und privaten Schlüssel abrufen
                            string publicKey = rsa.ToXmlString(false); // Nur öffentlicher Schlüssel
                            string privateKey = rsa.ToXmlString(true); // Öffentlicher und privater Schlüssel

                            // Verschlüsseln mit dem öffentlichen Schlüssel
                            string encryptedText = EncryptRSA(plaintext, publicKey);
                            Console.WriteLine($"Encrypted text (RSA): {encryptedText}");

                            // Entschlüsseln mit dem privaten Schlüssel
                            string decryptedText = DecryptRSA(encryptedText, privateKey);
                            Console.WriteLine($"Decrypted text (RSA): {decryptedText}");
                        }
                        finally
                        {
                            rsa.PersistKeyInCsp = false; // Schlüssel nicht im CSP speichern
                        }
                    }
                }
                else
                {
                    Console.WriteLine("Invalid option, please try again.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error has occurred: {ex.Message}");
            }

            Console.WriteLine("\nDo you want to repeat? (y/n): ");
            string repeat = Console.ReadLine()?.ToLower() ?? string.Empty;
            if (repeat != "y")
            {
                if (repeat == "n")
                {
                    Console.WriteLine("Programm terminated.");
                }
                break;
            }
        }
    }

    // Encrypts the given plain text using the provided public key
    public static string EncryptRSA(string plainText, string publicKey)
    {
        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
        {
            rsa.FromXmlString(publicKey);
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] encryptedBytes = rsa.Encrypt(plainBytes, false);
            return Convert.ToBase64String(encryptedBytes);
        }
    }

    // Decrypts the given encrypted text using the provided private key
    public static string DecryptRSA(string encryptedText, string privateKey)
    {
        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
        {
            rsa.FromXmlString(privateKey);
            byte[] encryptedBytes = Convert.FromBase64String(encryptedText);
            byte[] decryptedBytes = rsa.Decrypt(encryptedBytes, false);
            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }
}


public class HillCipher
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const int Mod = 26;
    private readonly int[,] K;
    private readonly int[,] KInv;
    private readonly int n;

    public HillCipher(int matrixSize, int[,]? keyMatrix = null)
    {
        if (keyMatrix != null)
        {
            if (keyMatrix.GetLength(0) != keyMatrix.GetLength(1))
                throw new ArgumentException("Key matrix must be square.");

            if (keyMatrix.GetLength(0) != matrixSize)
                throw new ArgumentException("Matrix size must match the dimensions of the key matrix.");

            n = matrixSize;
            K = keyMatrix;
            var det = Determinant(K);
            Console.WriteLine($"Determinant: {det}");

            if (GCD(det, Mod) != 1)
                throw new ArgumentException("Matrix is not invertible mod 26");

            int detInv = ModularInverse(det, Mod);
            Console.WriteLine($"Modular Inverse of Determinant: {detInv}");

            KInv = InverseMatrix(K);

            // Debug: Ausgabe der inversen Matrix
            Console.WriteLine("Inverse Matrix:");
            for (int i = 0; i < KInv.GetLength(0); i++)
            {
                for (int j = 0; j < KInv.GetLength(1); j++)
                {
                    Console.Write(KInv[i, j] + " ");
                }
                Console.WriteLine();
            }
        }
        else
        {
            n = matrixSize;
            K = GenerateRandomKey();
            KInv = InverseMatrix(K);
        }
    }

    // Get the key matrix
    public int[,] GetKeyMatrix()
    {
        return K;
    }

    // Generate a random key matrix of size n x n
    private int[,] GenerateRandomKey()
    {
        var random = new Random();
        int[,] key;
        while (true)
        {
            key = new int[n, n];
            for (int i = 0; i < n; i++)
                for (int j = 0; j < n; j++)
                    key[i, j] = random.Next(1, Mod);

            var det = Determinant(key);
            if (GCD(det, Mod) == 1) break;
        }
        return key;
    }

    // Prepare the text by removing spaces and padding with 'X' if necessary
    public string Encrypt(string plaintext)
    {
        plaintext = PrepareText(plaintext);
        var ciphertext = new StringBuilder();

        for (int i = 0; i < plaintext.Length; i += n)
        {
            var block = plaintext.Substring(i, Math.Min(n, plaintext.Length - i));
            var numbers = TextToNumbers(block);
            var encrypted = MatrixMultiply(numbers, K);
            ciphertext.Append(NumbersToText(encrypted));
        }

        return ciphertext.ToString();
    }

    // Convert text to numbers based on the alphabet
    private int[] TextToNumbers(string text)
    {
        var numbers = new int[text.Length];
        for (int i = 0; i < text.Length; i++)
            numbers[i] = Alphabet.IndexOf(char.ToUpper(text[i]));
        return numbers;
    }

    // Convert numbers back to text
    private string NumbersToText(int[] numbers)
    {
        var sb = new StringBuilder();
        foreach (var num in numbers)
            sb.Append(Alphabet[num % Mod]);
        return sb.ToString();
    }

    // Multiply a vector by a matrix
    private int[] MatrixMultiply(int[] vector, int[,] matrix)
    {
        int size = matrix.GetLength(0);
        if (vector.Length != size)
            throw new ArgumentException($"Vector length ({vector.Length}) must match matrix size ({size}).");

        int[] result = new int[size];
        for (int i = 0; i < size; i++)
        {
            int sum = 0;
            for (int j = 0; j < size; j++)
            {
                sum += vector[j] * matrix[i, j];
            }
            result[i] = sum % Mod;
            if (result[i] < 0) result[i] += Mod; // Ensure no negative values
        }
        return result;
    }

    // Calculate the determinant of a matrix using recursion
    private int Determinant(int[,] matrix)
    {
        int size = matrix.GetLength(0);
        if (size != matrix.GetLength(1))
            throw new ArgumentException("Matrix must be square.");

        if (size == 2)
            return matrix[0, 0] * matrix[1, 1] - matrix[0, 1] * matrix[1, 0];

        int det = 0;
        for (int i = 0; i < size; i++)
        {
            int[,] sub = CreateSubMatrix(matrix, 0, i);
            det += (int)Math.Pow(-1, i) * matrix[0, i] * Determinant(sub);
        }
        return det;
    }

    // Calculate the inverse of a matrix using the adjugate method
    private int[,] InverseMatrix(int[,] matrix)
    {
        int det = Determinant(matrix) % Mod;
        if (det < 0) det += Mod; // Ensure determinant is positive
        int detInv = ModularInverse(det, Mod);
        int[,] adjugate = AdjugateMatrix(matrix); // Use generalized adjugate for any size

        int size = matrix.GetLength(0);
        int[,] inverse = new int[size, size];
        for (int i = 0; i < size; i++)
        {
            for (int j = 0; j < size; j++)
            {
                inverse[i, j] = (adjugate[i, j] * detInv) % Mod;
                if (inverse[i, j] < 0) inverse[i, j] += Mod; // Ensure no negative values
            }
        }

        return inverse;
    }

    // Calculate the adjugate matrix using cofactors
    public int[,] AdjugateMatrix(int[,] matrix)
    {
        int size = matrix.GetLength(0);
        if (size != matrix.GetLength(1))
            throw new ArgumentException("Matrix must be square.");

        int[,] adjugate = new int[size, size];
        for (int i = 0; i < size; i++)
        {
            for (int j = 0; j < size; j++)
            {
                int[,] minor = CreateSubMatrix(matrix, i, j);
                adjugate[j, i] = (int)Math.Pow(-1, i + j) * Determinant(minor); // Transpose and cofactor
                adjugate[j, i] = adjugate[j, i] % Mod;
                if (adjugate[j, i] < 0) adjugate[j, i] += Mod;
            }
        }
        return adjugate;
    }

    // Calculate the modular inverse of a number using brute force
    private int ModularInverse(int a, int m)
    {
        a = a % m;
        for (int x = 1; x < m; x++)
            if ((a * x) % m == 1)
                return x;
        return 1;
    }

    // Prepare the plaintext by removing spaces and padding with 'X' if necessary
    private string PrepareText(string text)
    {
        text = text.ToUpper().Replace(" ", "");
        int padding = n - (text.Length % n);
        if (padding != n) text += new string('X', padding); // Pad with 'X' to match block size
        return text;
    }

    // Decrypt the ciphertext using the inverse key matrix
    public string Decrypt(string ciphertext)
    {
        var plaintext = new StringBuilder();

        for (int i = 0; i < ciphertext.Length; i += n)
        {
            var block = ciphertext.Substring(i, Math.Min(n, ciphertext.Length - i));
            var numbers = TextToNumbers(block);
            var decrypted = MatrixMultiply(numbers, KInv);
            plaintext.Append(NumbersToText(decrypted));
        }

        // Entfernen des Paddings
        return plaintext.ToString().TrimEnd('X');
    }

    // Create a submatrix by excluding the specified row and column
    private int[,] CreateSubMatrix(int[,] matrix, int excludeRow, int excludeCol)
    {
        int size = matrix.GetLength(0);
        int[,] subMatrix = new int[size - 1, size - 1];
        for (int i = 0, subI = 0; i < size; i++)
        {
            if (i == excludeRow) continue;
            for (int j = 0, subJ = 0; j < size; j++)
            {
                if (j == excludeCol) continue;
                subMatrix[subI, subJ++] = matrix[i, j];
            }
            subI++;
        }
        return subMatrix;
    }

    // Greatest Common Divisor
    private static int GCD(int a, int b) => b == 0 ? a : GCD(b, a % b);
}