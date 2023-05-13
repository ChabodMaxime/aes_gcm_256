using System;
using System.Text;
using System.Security.Cryptography;


namespace AesGcm256
{
    static class Cryptor
    {
        static void Main(string[] args)
        {
            var text = "Difficile de prétendre cuisiner un vrai döner kebab si on ne possède pas la fameuse rôtissoire à broche verticale mais on peut toujours s’en rapprocher.\r\n\r\n1 kilo de viande de mouton (ou de veau ou des deux) découpée en fines lamelles.\r\nPour la marinade: jus de 2 oignons, 1 gousse d’ail, du jus de citron, 1 cuillère à café de thym[1], une pincée de piment, sel, poivre, une cuillère à soupe d’huile d'olive, une cuillère à soupe de lait.\r\nLaisser mariner la viande toute la nuit.\r\nFaire revenir les lanières à feu vif dans une poêle avec une tomate concassée.\r\nPrendre 500 g de yaourt à la grecque (qui ressemble davantage au yaourt utilisé en Turquie). Etaler le yaourt dans le pide (ou sur une crêpe de blé noir), mettre la viande et la tomate (ou dessus), éventuellement une feuille de salade et quelques tranches d’oignons. On peut ajouter un piment vert si on en trouve.\r\nMais plus on ajoute d’ingrédients supplémentaires (choux, etc) et de sauces (mayonnaise, ketchup, sauce blanche, etc) plus on s’éloigne de la recette originelle du döner kebab";

            //Instance de la classe EncryptAES crée dans ce script
            var cryptor = new EncryptAES();

            //Création d'une variable hébergeant un tableau d'octet pour la clé de chiffrement privée
            var private_key = new byte[32];  //32 octet soit 256 bits
            

            //Remplissage du tableau avec une fonction de génération d'octets aléatoires cryptographiquement forts appartenant à la lib System.Security.Cryptography
            RandomNumberGenerator.Fill(private_key);
            //Transformation de la clé privée en base64 pour l'utilisateur
            var private_key_backup = Convert.ToBase64String(private_key);

            //Création du nonce conforme au NIST SP 800-38D
            var IV = new byte[AesGcm.NonceByteSizes.MaxSize];
            RandomNumberGenerator.Fill(IV);


            //Initialisation de la clé d'authentification suplémentaire basée sur l'algorithme base64, randomisée puis transformée en tableau d'octets.
            var authdata = Encoding.UTF8.GetBytes("TnojN2dKVW1MbjlDP0RrT3hvZzVAJEBRcg==");
            RandomNumberGenerator.Fill(authdata);

            //Création de la variable à sorti "output_crypt", appelant la classe EncryptAES et la méthode encrypt (push)
            (byte[] ciphereText, byte[] TAG) output_crypt = cryptor.push(Encoding.UTF8.GetBytes(text), private_key, IV, authdata);

            //Déchiffrement du texte en fournissant le TAG, la clé privée et le nonce
            byte[] raw_data = cryptor.back(output_crypt.ciphereText, private_key, IV, output_crypt.TAG, authdata);


            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
            string ascii = $@"
                       _____                  ___  _____   __       
     /\               / ____|                |__ \| ____| / /   _   
    /  \   ___  ___  | |  __  ___ _ __ ___      ) | |__  / /_ _| |_ 
   / /\ \ / _ \/ __| | | |_ |/ __| '_ ` _ \    / /|___ \| '_ \_   _|
  / ____ \  __/\__ \ | |__| | (__| | | | | |  / /_ ___) | (_) ||_|  
 /_/    \_\___||___/  \_____|\___|_| |_| |_| |____|____/ \___/      
                                                                    
                                                                    
";
            Console.WriteLine(ascii);
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
            Console.WriteLine("");
            Console.WriteLine($"## IV instance : {Encoding.UTF8.GetString(IV)}  ##");
            Console.WriteLine("");
            Console.WriteLine($"## Clé privée de chiffrement : {private_key_backup}  ##");
            Console.WriteLine("");
            Console.WriteLine($"## Clé d'authentification supplémentaire : {Encoding.UTF8.GetString(authdata)}  ##");
            Console.WriteLine("");
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
            Console.WriteLine($"## Votre texte chiffré avec AES GCM 256bits converti en base64 ##");
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
            Console.WriteLine("");
            Console.WriteLine($"##  {Convert.ToBase64String(output_crypt.ciphereText)}  ##");
            Console.WriteLine("");
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
            Console.WriteLine($"## Le texte avant chiffrement ##");
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
            Console.WriteLine("");
            Console.WriteLine($"##  {Encoding.UTF8.GetString(raw_data)}  ##");


        }

        //Création de la classe Encrypt de porté public
        public class EncryptAES
        {

            //Création de la méthode push de porté public retournant 2 tableau d'octets, et prenant en entrée 4 tableau d'octets servant au chiffrement
            public (byte[], byte[]) push(byte[] data, byte[] key, byte[] IV, byte[] associatedData)
            {
              
                //Instance de la classe AesGcm avec la clé de chiffrement privée fournit en paramètre le tout dans un using
                using (AesGcm aesgcm = new AesGcm(key))
                {
                    // Generation du TAG d'authentification via un tableau d'octet grace à la fonction TagByteSizes
                    byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];
                    //Génération d'un tableau d'octet de la taille du texte
                    byte[] ciphertext = new byte[data.Length];

                    //Appel de la méthode Encrypt de la classe .NET AesGcm
                    aesgcm.Encrypt(IV, data, ciphertext, tag, associatedData);

                    return (ciphertext, tag);
                }

               
            }

            // Création de la méthode back de porté public retournant 1 tableau d'octets, et prenant en entrée 5 tableau d'octets servant au chiffrement
            public byte[] back(byte[] cipherText, byte[] key, byte[] nonce, byte[] tag, byte[] associatedData)
            {
                //Création d'un tableau d'octet ayant la taille du bloc d'octet du texte chiffré
                byte[] raw_data = new byte[cipherText.Length];

                //Instance de la classe AesGcm dans la variable aes avec la clé de chiffrement privée fournit en paramètre le tout dans un using
                using (AesGcm aesGcm = new AesGcm(key))
                {
                    //Appel de la méthode Decrypt de la classe .NET AesGcm
                    aesGcm.Decrypt(nonce, cipherText, tag, raw_data, associatedData);
                }

                return raw_data;
            }
        }
    }
}
