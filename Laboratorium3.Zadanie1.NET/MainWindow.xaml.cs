// Importowanie potrzebnych przestrzeni nazw
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;

namespace zaliczenie.SzyfrowanieTekstu.ZuzannaLukiewska;

public partial class MainWindow : Window
{
    private readonly Stopwatch _stoper; // Stoper do mierzenia czasu operacji
    private SymmetricAlgorithm _algorytm;
    private double _czasDeszyfrowania;
    private double _czasSzyfrowania;

    public MainWindow()
    {
        InitializeComponent();
        algorithmComboBox.Items.Add("AES");
        algorithmComboBox.Items.Add("DES");
        algorithmComboBox.Items.Add("RC2");
        algorithmComboBox.Items.Add("Rijndael");
        algorithmComboBox.Items.Add("TripleDES");
        algorithmComboBox.SelectedIndex = 0;
        _stoper = new Stopwatch();
        UstawAlgorytm(); // Ustawienie domyślnego algorytmu
    }

    // Metoda ustawiająca algorytm symetryczny
    private void UstawAlgorytm()
    {
        _algorytm = algorithmComboBox.SelectedItem switch
        {
            "AES" => Aes.Create(),
            "DES" => DES.Create(),
            "RC2" => RC2.Create(),
            "Rijndael" => Rijndael.Create(),
            "TripleDES" => TripleDES.Create(),
            _ => throw new InvalidOperationException("Nieobsługiwany algorytm")
        };

        keyTextBox.Text = BitConverter.ToString(_algorytm.Key).Replace("-", "");
        ivTextBox.Text = BitConverter.ToString(_algorytm.IV).Replace("-", "");
    }

    // Obsługa zmiany wyboru algorytmu w ComboBox
    private void OnAlgorithmSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        UstawAlgorytm();
    }

    // Generowanie nowego klucza i IV
    private void OnGenerateKeyAndIVButtonClick(object sender, RoutedEventArgs e)
    {
        _algorytm.GenerateKey();
        _algorytm.GenerateIV();

        keyTextBox.Text = BitConverter.ToString(_algorytm.Key).Replace("-", "");
        ivTextBox.Text = BitConverter.ToString(_algorytm.IV).Replace("-", "");
    }

    // Obsługa przycisku szyfrowania
    private void OnEncryptButtonClick(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(plaintextTextBox.Text))
        {
            MessageBox.Show(
                "Proszę wprowadzić tekst jawny do zaszyfrowania.",
                "Błąd",
                MessageBoxButton.OK,
                MessageBoxImage.Error
            );
            return;
        }

        _stoper.Restart();
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintextTextBox.Text);
        var ciphertextBytes = ZaszyfrujTekst(
            plaintextBytes,
            _algorytm.Key,
            _algorytm.IV,
            _algorytm
        );
        _stoper.Stop();
        _czasSzyfrowania = _stoper.Elapsed.TotalMilliseconds;

        ciphertextTextBox.Text = Convert.ToBase64String(ciphertextBytes);
        ciphertextHexTextBox.Text = BitConverter.ToString(ciphertextBytes).Replace("-", "");
    }

    // Obsługa przycisku deszyfrowania
    private void OnDecryptButtonClick(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(ciphertextHexTextBox.Text))
        {
            MessageBox.Show(
                "Proszę wprowadzić tekst zaszyfrowany do odszyfrowania.",
                "Błąd",
                MessageBoxButton.OK,
                MessageBoxImage.Error
            );
            return;
        }

        _stoper.Restart();
        var ciphertextBytes = StringToByteArray(ciphertextHexTextBox.Text);
        var plaintextBytes = OdszyfrujTekst(
            ciphertextBytes,
            _algorytm.Key,
            _algorytm.IV,
            _algorytm
        );
        _stoper.Stop();
        _czasDeszyfrowania = _stoper.Elapsed.TotalMilliseconds;

        plaintextTextBox.Text = Encoding.UTF8.GetString(plaintextBytes);
        plaintextHexTextBox.Text = BitConverter.ToString(plaintextBytes).Replace("-", "");
    }

    // Metoda do szyfrowania danych
    private static byte[] ZaszyfrujTekst(
        byte[] plainTextBytes,
        byte[] Key,
        byte[] IV,
        SymmetricAlgorithm algorithm
    )
    {
        if (plainTextBytes == null || plainTextBytes.Length <= 0)
            throw new ArgumentNullException(nameof(plainTextBytes));
        if (Key == null || Key.Length <= 0)
            throw new ArgumentNullException(nameof(Key));
        if (IV == null || IV.Length <= 0)
            throw new ArgumentNullException(nameof(IV));

        using var encryptor = algorithm.CreateEncryptor(Key, IV);
        using var msEncrypt = new MemoryStream();
        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
        {
            csEncrypt.Write(plainTextBytes, 0, plainTextBytes.Length);
            csEncrypt.FlushFinalBlock();
        }

        return msEncrypt.ToArray();
    }

    // Metoda do deszyfrowania danych
    private static byte[] OdszyfrujTekst(
        byte[] cipherTextBytes,
        byte[] Key,
        byte[] IV,
        SymmetricAlgorithm algorithm
    )
    {
        if (cipherTextBytes == null || cipherTextBytes.Length <= 0)
            throw new ArgumentNullException(nameof(cipherTextBytes));
        if (Key == null || Key.Length <= 0)
            throw new ArgumentNullException(nameof(Key));
        if (IV == null || IV.Length <= 0)
            throw new ArgumentNullException(nameof(IV));

        using var decryptor = algorithm.CreateDecryptor(Key, IV);
        using var msDecrypt = new MemoryStream(cipherTextBytes);
        using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
        using var msPlainText = new MemoryStream();
        csDecrypt.CopyTo(msPlainText);
        return msPlainText.ToArray();
    }

    // Konwersja ciągu heksadecymalnego na tablicę bajtów
    private static byte[] StringToByteArray(string hex)
    {
        var numberChars = hex.Length;
        var bytes = new byte[numberChars / 2];
        for (var i = 0; i < numberChars; i += 2)
            bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
        return bytes;
    }
}
