using Encryption;

namespace Encription;

public class CliMenu {
    private byte[] _key;
    
    public CliMenu(byte[] key) {
        this._key = key;
    }

    public void ShowOptions() {
        Console.WriteLine("1: Safely store message");
        Console.WriteLine("2: Read message");
        Console.WriteLine("0: Exit");
    }

    public void HandleOption() {
        string option = Console.ReadLine();
        MessageProcess messageProcess = new MessageProcess(_key);

        switch (option) {
            case "1":
                Console.WriteLine("Type a message to encrypt:");
                string message = Console.ReadLine();
                messageProcess.EncryptAndSaveMessage(message);
                break;
            case "2":
                Console.WriteLine(messageProcess.ReadAndDecryptMessage());
                break;
            case "0":
                Environment.Exit(0);
                break;
            default:
                Console.WriteLine("Invalid option");
                break;
        }
    }
}