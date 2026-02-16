using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Text.RegularExpressions;

class Program
{
    static int userMessageCount = 0;
    static bool running = true;
    static int shameCount = 1;

    static void Main()
    {
        string channel = "#hello";
        string server = "connect.divanodivino.xyz";
        int port = 6667;
        string nick = "anon_" + new Random().Next(1000, 9999);
        string shamePrefix = "Hi, I'm running an untrusted binary I found on the internet.";

        Console.CancelKeyPress += (sender, e) =>
        {
            running = false;
            Console.WriteLine($"\nTotal messages sent: {userMessageCount}");
        };

        try
        {
            using (TcpClient client = new TcpClient(server, port))
            using (NetworkStream stream = client.GetStream())
            using (StreamWriter writer = new StreamWriter(stream, new UTF8Encoding(false)) { AutoFlush = true })
            using (StreamReader reader = new StreamReader(stream, Encoding.UTF8))
            {
                writer.WriteLine("PASS D1av0laSauce!");
                writer.WriteLine($"NICK {nick}");
                writer.WriteLine($"USER {nick} 0 * :{nick}");

                var readerThread = new Thread(() => 
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        if (line.StartsWith("PING"))
                        {
                            writer.WriteLine(line.Replace("PING", "PONG"));
                            continue;
                        }

                        var msgMatch = Regex.Match(line, @"^:([^!]+)!.* PRIVMSG #[^ ]+ :(.+)$");
                        if (msgMatch.Success)
                        {
                            string sender = msgMatch.Groups[1].Value;
                            string message = msgMatch.Groups[2].Value;

                            if (message.StartsWith(shamePrefix))
                                continue;

                            Console.Write("\r" + new string(' ', Console.WindowWidth) + "\r");
                            Console.WriteLine($"{sender}: {message}");
                            Console.Write("> ");
                        }
                    }
                });
                readerThread.IsBackground = true;
                readerThread.Start();

                Thread.Sleep(1500);
                writer.WriteLine($"JOIN {channel}");

                string firstShame = $"{shamePrefix} [{shameCount}] ^_*";
                writer.WriteLine($"PRIVMSG {channel} :{firstShame}");
                shameCount++;

                var shameThread = new Thread(() =>
                {
                    while (running)
                    {
                        Thread.Sleep(60000); 
                        string fullShame = $"{shamePrefix} [{shameCount}] ^_*";
                        writer.WriteLine($"PRIVMSG {channel} :{fullShame}");
                        shameCount++;
                    }
                });
                shameThread.IsBackground = true;
                shameThread.Start();

                Console.Write("> ");
                while (running)
                {
                    string input = Console.ReadLine();
                    if (!string.IsNullOrWhiteSpace(input))
                    {
                        writer.WriteLine($"PRIVMSG {channel} :{input}");
                        userMessageCount++;
                    }
                    Console.Write("> ");
                }
            }
        }
        catch
        {

        }

    }
}
