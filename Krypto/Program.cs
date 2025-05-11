using System;
using System.Collections.Generic;
using System.Text;

public class Program
{
    public static void Main(string[] args)
    {
        try
        {
            // Example key matrix for a 4x4 Hill Cipher
            int[,] keyMatrix = {
            { 20, 2, 1, 21 },
            { 16, 11, 25, 20 },
            { 14, 18, 7, 12 },
            { 25, 22, 23, 4 }
        };

            // Create an instance of HillCipher with a 4x4 matrix
            HillCipher cipher = new HillCipher(4, keyMatrix);

            // Example plaintext
            string plaintext = "TREFFE KONTAKTPERSON UM DREI UHR IM STADTPARK";

            // Encrypt the plaintext
            string encryptedText = cipher.Encrypt(plaintext);
            Console.WriteLine($"Plaintext: {plaintext}");
            Console.WriteLine($"Encrypted Text: {encryptedText}");

            // Decrypt the ciphertext
            string decryptedText = cipher.Decrypt(encryptedText);
            Console.WriteLine($"Decrypted Text: {decryptedText}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An error occurred: {ex.Message}");
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

    private int[] TextToNumbers(string text)
    {
        var numbers = new int[text.Length];
        for (int i = 0; i < text.Length; i++)
            numbers[i] = Alphabet.IndexOf(char.ToUpper(text[i]));
        return numbers;
    }

    private string NumbersToText(int[] numbers)
    {
        var sb = new StringBuilder();
        foreach (var num in numbers)
            sb.Append(Alphabet[num % Mod]);
        return sb.ToString();
    }

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

    public int[,] AdjugateMatrix(int[,] matrix) // Sichtbarkeit auf public geändert
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

    private int ModularInverse(int a, int m)
    {
        a = a % m;
        for (int x = 1; x < m; x++)
            if ((a * x) % m == 1)
                return x;
        return 1;
    }

    private string PrepareText(string text)
    {
        text = text.ToUpper().Replace(" ", "");
        int padding = n - (text.Length % n);
        if (padding != n) text += new string('X', padding); // Pad with 'X' to match block size
        return text;
    }

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

    // For a 2×2 matrix [[a, b], [c, d]], the adjugate is [[d, -b], [-c, a]]
    // For a 2×2 matrix [[a, b], [c, d]], the adjugate is [[d, -b], [-c, a]]
    //public int[,] AdjugateMatrix2x2(int[,] matrix) // Sichtbarkeit auf public geändert
    //{
    //    int[,] adjugate = new int[2, 2];
    //    adjugate[0, 0] = matrix[1, 1];
    //    adjugate[0, 1] = -matrix[0, 1];
    //    adjugate[1, 0] = -matrix[1, 0];
    //    adjugate[1, 1] = matrix[0, 0];

    //    // Apply modulo to ensure positive values
    //    for (int i = 0; i < 2; i++)
    //        for (int j = 0; j < 2; j++)
    //        {
    //            adjugate[i, j] = adjugate[i, j] % Mod;
    //            if (adjugate[i, j] < 0) adjugate[i, j] += Mod;
    //        }

    //    return adjugate;
    //}



    private static int GCD(int a, int b) => b == 0 ? a : GCD(b, a % b);
}