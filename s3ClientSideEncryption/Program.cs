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
        //Encryption context needs to be a json string, both the key and the value can be changed
        static string jsonStringEncryptionContext = "{\"customContext\": \"This is my context, there are many like it but this one is mine \"}";


        public static void Main(string[] args)
        {
            string filePath = args.Any() ? args[0] : "";
            if (string.IsNullOrEmpty(filePath) || !System.IO.File.Exists(filePath))
            {
                Console.WriteLine($"invalid file name {filePath}");
                Console.ReadKey();

            }
            UploadFileWithClientSideEncryption(filePath);

        }

     
        static void UploadFileWithClientSideEncryption(string filePath)
        {
            string kmsKeyID = "";
          

            var objectKey = System.IO.Path.GetFileName(filePath);

            using (var kmsClient = new AmazonKeyManagementServiceClient(defaultEndpoint))
            {

             
                kmsKeyID = GetKeyByAlias(keyName, kmsClient);
                var kmsEncryptionMaterials = new EncryptionMaterials(kmsKeyID);
                                  

                using (var s3Client = new AmazonS3EncryptionClient(defaultEndpoint, kmsEncryptionMaterials))
                {

                    // encrypt and put object
                    var putRequest = new PutObjectRequest
                    {
                        BucketName = bucketName,
                        Key = objectKey,
                        FilePath = filePath
                    };

                    //Set the master key id for the key you want to use, each object will be encrypted with its own data key
                    putRequest.Headers["x-amz-server-side-encryption-aws-kms-key-id"] = kmsKeyID;
                    //SET the encryption context header
                    putRequest.Headers["x-amz-server-side-encryption-context"] = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(jsonStringEncryptionContext));

                    //Set the server side encryption mode to KMS
                    putRequest.Headers["x-amz-server-side-encryption"] = "aws:kms";
                    
                    


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
                    //You don't have to re-set all of the headers here because the S3EncryptionClient reads the metadata automatically and uses it to preform the decryption

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
                return  foundAlias.TargetKeyId;
                //    var keyData = client.DescribeKeyAsync(keyID).GetAwaiter().GetResult();
                //    return keyData?;
                //
            }

            return null;
        }

    }
}
