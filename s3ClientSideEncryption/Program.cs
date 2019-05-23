using System;
using System.Collections.Specialized;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;

using Amazon;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.S3.Encryption;
using Amazon.S3.Transfer;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;

namespace s3ClientSideEncryption
{
    class Program
    {
        static string bucketName = "aaa-ndc-demo-bucket";

        static string keyName = "NetDataEncryptionKeyForLegacyApplication";

        static Amazon.RegionEndpoint defaultEndpoint = Amazon.RegionEndpoint.USEast1;

        static string jsonStringEncryptionContext = "{\"customContext\": \"This is my context, there are many like it but this one is mine \"}";


        public static void Main(string[] args)
        {
            string filePath = args.Any() ? args[0] : "";
            if (string.IsNullOrEmpty(filePath) || !System.IO.File.Exists(filePath))
            {
                Console.WriteLine($"invalid file name {filePath}");
                Console.ReadKey();

            }
             ClientSideEncryptWithKMSThenUpload(filePath);
            //UploadFileWithClientSideEncryption(filePath);

        }

        static void ClientSideEncryptWithKMSThenUpload(string filePath)
        {
            UploadManualEncrypt(filePath);

            DownloadManualEncrypt(filePath);


        }
        //This is the context I am using for the example, use whatever you want, just know the key value pairs must match (including case) exactly
        static string myContext = "This is my Context, there are many like it, but this one is mine";
        static void UploadManualEncrypt(string filePath)
        {
            string kmsKeyID = "";
            var objectKey = System.IO.Path.GetFileName(filePath);

            using (var aes = Aes.Create())
            using (var kmsClient = new AmazonKeyManagementServiceClient(defaultEndpoint))
            {
                //Get the key from KMS
                kmsKeyID = GetKeyByAlias(keyName, kmsClient);
                //Generate a data key for the specific object
                var dataKeyRequest = new GenerateDataKeyRequest();
                dataKeyRequest.KeyId = kmsKeyID;
                dataKeyRequest.KeySpec = DataKeySpec.AES_256;
                //Set the encryption context for your AAD
                dataKeyRequest.EncryptionContext["MyContext"] = myContext;
                var dataKeyResponse = kmsClient.GenerateDataKeyAsync(dataKeyRequest).GetAwaiter().GetResult();

                var fileData = new FileStream(filePath, FileMode.Open, FileAccess.Read);
                Stream output = new MemoryStream();
                //Write the length of the encrypted key first so we can retrieve it later
                output.WriteByte((byte)dataKeyResponse?.CiphertextBlob?.Length);
                //Write the encrypted key to next
                dataKeyResponse.CiphertextBlob.CopyTo(output);
                aes.Key = dataKeyResponse.Plaintext.ToArray();
                //Then write the IV, since IV is fixed length we don't have to worry about storing the IV length
                output.Write(aes.IV, 0, aes.IV.Length);
                using (var cs = new CryptoStream(output, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    //Now encrypt the file data into the stream
                    fileData.CopyTo(cs);
                    cs.FlushFinalBlock();


                    using (var s3client = new AmazonS3Client(defaultEndpoint))
                    {
                        var putRequest = new PutObjectRequest
                        {
                            BucketName = bucketName,
                            Key = objectKey,
                            InputStream = output

                        };


                        //All of this metadata is optional, you do not have to include any of this
                        //I am just putting it here if you want to store it in the metadata along with the object
                        //The encrypted data key and IV are already stored with the file, you will need a way to look up the context and keyid
                        putRequest.Metadata.Add("x-amz-meta-client-side-encryption-context", myContext);
                        putRequest.Metadata.Add("x-amz-meta-client-side-encryption-aws-kms-key-id", kmsKeyID);
                        putRequest.Metadata.Add("x-amz-meta-cipherblob", Convert.ToBase64String(dataKeyResponse.CiphertextBlob.ToArray()));
                        putRequest.Metadata.Add("x-amz-meta-x-amz-iv", Convert.ToBase64String(aes.IV));
                       

                        s3client.PutObjectAsync(putRequest).GetAwaiter().GetResult();
                    }
                }

            }
        }

     
        static void DownloadManualEncrypt(string filePath)
        {
            string objectKey = System.IO.Path.GetFileName(filePath);

            using (var s3c = new AmazonS3Client(defaultEndpoint))
            using (var aes = Aes.Create())
            using (var kmsClient = new AmazonKeyManagementServiceClient(defaultEndpoint))
            {

                //Get the encrypted file
                var getRequest = new GetObjectRequest();
                getRequest.BucketName = bucketName;
                getRequest.Key = objectKey;
                var s3Response = s3c.GetObjectAsync(getRequest).GetAwaiter().GetResult();


                using (var algorithm = Aes.Create())
                {
                    //Get the length of the encrypted key
                    var length = s3Response.ResponseStream.ReadByte();
                   //read in the encrypted key
                    var buffer = new byte[length];
                    s3Response.ResponseStream.Read(buffer, 0, length);
                  
                    DecryptRequest decryptRequest = new DecryptRequest()
                    {
                        CiphertextBlob = new MemoryStream(buffer),
                        

                    };
                    //All you need to supply is the context
                    decryptRequest.EncryptionContext["MyContext"] = myContext;

                    var decryptedData = kmsClient.DecryptAsync(decryptRequest).GetAwaiter().GetResult();
                    algorithm.Key = decryptedData.Plaintext.ToArray();
                    var iv = algorithm.IV;
                    //The IV is inbedded into the file when uploaded
                    s3Response.ResponseStream.Read(iv, 0, iv.Length);
                    algorithm.IV = iv;
                    string outputPath = System.IO.Path.Combine(System.IO.Path.GetDirectoryName(filePath), System.IO.Path.GetFileNameWithoutExtension(filePath) + "_" + new Random().Next(0, 1000).ToString() + System.IO.Path.GetExtension(filePath));

                  //decrypt and write to a local file
                    using (var cryptoStream = new CryptoStream(s3Response.ResponseStream,
                        algorithm.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        using (var fileStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write))
                        {
                            cryptoStream.CopyTo(fileStream);
                            fileStream.Flush();
                            fileStream.Close();
                        }
                    }

                    Console.WriteLine($"Wrote file to {outputPath}");
                }


              
            }
        }


        static void UploadFileWithClientSideEncryption(string filePath)
        {
            string kmsKeyID = null;


            var objectKey = System.IO.Path.GetFileName(filePath);

            using (var kmsClient = new AmazonKeyManagementServiceClient(defaultEndpoint))
            {

                // var response = kmsClient.CreateKeyAsync(new CreateKeyRequest()).GetAwaiter().GetResult();

                kmsKeyID = GetKeyByAlias(keyName, kmsClient);


                //  var keyMetadata = keyData?.KeyMetadata; // An object that contains information about the CMK created by this operation.

                var kmsEncryptionMaterials = new EncryptionMaterials(kmsKeyID);



                //set encryption context



                using (var s3Client = new AmazonS3EncryptionClient(defaultEndpoint, kmsEncryptionMaterials))
                {

                    // encrypt and put object
                    var putRequest = new PutObjectRequest
                    {
                        BucketName = bucketName,
                        Key = objectKey,
                        FilePath = filePath
                    };
                    putRequest.Metadata.Add("x-amz-meta-moo", "This is a test");
                    //      putRequest.Headers["x-amz-matdesc"] = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(jsonStringEncryptionContext));
                    putRequest.Headers["x-amz-server-side-encryption"] = "aws:kms";
                    putRequest.Headers["x-amz-server-side-encryption-aws-kms-key-id"] = kmsKeyID;
                    putRequest.Headers["x-amz-server-side-encryption-context"] = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(jsonStringEncryptionContext));



                    s3Client.PutObjectAsync(putRequest).GetAwaiter().GetResult();
                }
                // The KeyID is actually embedded in the metadata of the object and the encryptionclient automatically looks it up so you don't actually have to do that yourself

                var kem2 = new EncryptionMaterials("1111111-11111-11111111-11111111");



                using (var s3Client2 = new AmazonS3EncryptionClient(defaultEndpoint, kem2))
                {


                    // get object and decrypt
                    var getRequest = new GetObjectRequest
                    {
                        BucketName = bucketName,
                        Key = objectKey
                    };

                    string fPath2 = System.IO.Path.Combine(System.IO.Path.GetDirectoryName(filePath), System.IO.Path.GetFileNameWithoutExtension(filePath) + "_" + new Random().Next(0, 1000).ToString() + System.IO.Path.GetExtension(filePath));

                    using (var getResponse = s3Client2.GetObjectAsync(getRequest).GetAwaiter().GetResult())
                    using (var stream = getResponse.ResponseStream)
                    using (var reader = new StreamReader(stream))
                    {
                        using (var fileStream = new FileStream(fPath2, FileMode.Create, FileAccess.Write))
                        {
                            stream.CopyTo(fileStream);
                            fileStream.Flush();
                            fileStream.Close();
                        }

                    }
                    Console.WriteLine($"Object written to {fPath2}");

                }
            }

            Console.WriteLine("Press any key to continue...");
            Console.ReadKey();
        }

        static string GetKeyByAlias(string alias, AmazonKeyManagementServiceClient client)
        {
            //how does it know what credentials to use? - it first looks at app.config or webconfig, 
            // then the profile in the SDK Store, then the local credentials file
            //then the environment variables AWS_ACCESS_KEY_ID & AWS_SECRET_KEY, 
            // then finally it will look at the instance profile on an EC2 instance

            //since this is a demo / local we are going to use the default profile in the SDK store, 
            // for production we would use the local store on the EC2 instance
            //this should be transparent and allow for definition by environment


            var aliasResponse = client.ListAliasesAsync(new ListAliasesRequest() { Limit = 1000 }).GetAwaiter().GetResult();

            if (aliasResponse == null || aliasResponse.Aliases == null)
            {
                return null;
            }

            var foundAlias = aliasResponse.Aliases.Where(r => r.AliasName == "alias/" + alias).FirstOrDefault();
            if (foundAlias != null)
            {
                return foundAlias.TargetKeyId;
                //    var keyData = client.DescribeKeyAsync(keyID).GetAwaiter().GetResult();
                //    return keyData?;
                //
            }

            return null;
        }

    }
}
