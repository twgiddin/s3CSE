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
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;

namespace s3ClientSideEncryption
{
    class Program
    {
        static string bucketName = "aaa-ndc-demo-bucket";

        static string keyName = "NetDataEncryptionKeyForLegacyApplication";

       static Amazon.RegionEndpoint defaultEndpoint = Amazon.RegionEndpoint.USEast1;


        public static void Main(string[] args)
        {
            string kmsKeyID = null;
            string filePath = args.Any() ? args[0] : "";
            if (string.IsNullOrEmpty(filePath) || !System.IO.File.Exists(filePath))
            {
                Console.WriteLine($"invalid file name {filePath}");
                Console.ReadKey();

            }

            var objectKey = System.IO.Path.GetFileName(filePath);

            using (var kmsClient = new AmazonKeyManagementServiceClient(defaultEndpoint))
            {
                
               // var response = kmsClient.CreateKeyAsync(new CreateKeyRequest()).GetAwaiter().GetResult();

              var  keyData = GetKeyByAlias(keyName);

                kmsKeyID = keyData.KeyMetadata.KeyId;

                var keyMetadata = keyData?.KeyMetadata; // An object that contains information about the CMK created by this operation.
              
                var kmsEncryptionMaterials = new EncryptionMaterials(kmsKeyID);
                // CryptoStorageMode.ObjectMetadata is required for KMS EncryptionMaterials
                var config = new AmazonS3CryptoConfiguration()
                {
                    StorageMode = CryptoStorageMode.ObjectMetadata
                };


                using (var s3Client = new AmazonS3EncryptionClient(defaultEndpoint,  kmsEncryptionMaterials))
                {
                    // encrypt and put object
                    var putRequest = new PutObjectRequest
                    {
                        BucketName = bucketName,
                        Key = objectKey,
                        FilePath = filePath
                    };
                    s3Client.PutObjectAsync(putRequest).GetAwaiter().GetResult();

                    // get object and decrypt
                    var getRequest = new GetObjectRequest
                    {
                        BucketName = bucketName,
                        Key = objectKey
                    };

                    string fPath2 = System.IO.Path.Combine(System.IO.Path.GetDirectoryName(filePath), System.IO.Path.GetFileNameWithoutExtension(filePath) + "_" +  new Random().Next(0, 1000).ToString() +  System.IO.Path.GetExtension(filePath));
                    
                   using (var getResponse = s3Client.GetObjectAsync(getRequest).GetAwaiter().GetResult())
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

        static DescribeKeyResponse GetKeyByAlias(string alias)
        {
            //how does it know what credentials to use? - it first looks at app.config or webconfig, 
            // then the profile in the SDK Store, then the local credentials file
            //then the environment variables AWS_ACCESS_KEY_ID & AWS_SECRET_KEY, 
            // then finally it will look at the instance profile on an EC2 instance

            //since this is a demo / local we are going to use the default profile in the SDK store, 
            // for production we would use the local store on the EC2 instance
            //this should be transparent and allow for definition by environment

            var client = new AmazonKeyManagementServiceClient(defaultEndpoint);


            var aliasResponse = client.ListAliasesAsync(new ListAliasesRequest() { Limit = 1000 }).GetAwaiter().GetResult();

            if (aliasResponse == null || aliasResponse.Aliases == null)
            {
                return null;
            }

            var foundAlias = aliasResponse.Aliases.Where(r => r.AliasName == "alias/" + alias).FirstOrDefault();
            if (foundAlias != null)
            {
                string keyID =  foundAlias.TargetKeyId;
                var keyData = client.DescribeKeyAsync(keyID).GetAwaiter().GetResult();
                return keyData;
            }

            return null;
        }

    }
}
