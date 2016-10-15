using System;
using System.Linq;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using HpqPswdD.Native;

namespace HpqPswdD
{
	public static class Program
	{
		/// <summary>
		/// Cryptographic container identifier string to be used.
		/// </summary>
		private static string container = "HpqPswd";

		/// <summary>
		/// Contains the AES-256 key used to encrypt the passwords. The bytes
		/// can be mapped to a <c>BLOBHEADER</c> structure, followed by the
		/// length of the key and then by the key itself. The mapping of values
		/// is as follows.
		/// <c>
		/// typedef struct _PUBLICKEYSTRUC {
		///    BYTE   bType;    // 0x08 (PLAINTEXTKEYBLOB)
		///    BYTE   bVersion; // 0x02 (CUR_BLOB_VERSION)
		///    WORD   reserved; // 0x0000
		///    ALG_ID aiKeyAlg; // 0x00006610 (CALG_AES_256)
		/// } BLOBHEADER, PUBLICKEYSTRUC;
		/// </c>
		/// </summary>
		private static byte[] aesKeyData = new byte[] {
			0x08, 0x02, 0x00, 0x00, 0x10, 0x66, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
			0x4a, 0x14, 0xb6, 0x96, 0x32, 0xff, 0x83, 0x6b, 0x42, 0x88, 0xda, 0x79,
			0xa5, 0x49, 0xed, 0x9d, 0x1c, 0x0b, 0xd3, 0x77, 0x83, 0x9f, 0xe2, 0xd6,
			0x52, 0x54, 0x71, 0x0c, 0x3e, 0xbd, 0x1e, 0x33
		};

		/// <summary>
		/// The file containing the encrypted password has a specific format
		/// that includes a magic value of <c>_HPPW12_</c> (ASCII).
		/// </summary>
		private static byte[] fileMagicData = new byte[] {
			0x5f, 0x48, 0x50, 0x50, 0x57, 0x31, 0x32, 0x5f
		};

		private static string usage = "Decrypts passwords encrypted by the Hewlett-Packard password encryption utility.\n\nHPQPSWDD [drive:][path]filename";

		public static void Main(string[] arguments)
		{
			BinaryReader inputFileReader = null;
			// Using a 1 KiB buffer for reading the file.
			byte[]buffer = new byte[1024];
			// Will hold the number of KiB read from file.
			int read = 0;

			IntPtr provider = IntPtr.Zero;
			IntPtr cryptKey = IntPtr.Zero;

			try
			{
				if (arguments.Length < 1)
				{
					Console.WriteLine(usage);
				}
				else {
					FileInfo inputFileInfo = new FileInfo(arguments[0]);

					if (!inputFileInfo.Exists)
					{
						throw new Exception("File containing the password does not exist");
					}

					inputFileReader = new BinaryReader(new FileStream(inputFileInfo.FullName,
						FileMode.Open, FileAccess.Read), Encoding.ASCII);

					// TODO Could make this more efficient by reading the file
					// magic as a 64 bits unsigned integer.
					if ((read = inputFileReader.Read(buffer, 0, 8)) != 8)
					{
						throw new Exception(String.Format("Unable to read the file magic value (only read {0} bytes, expecting 8)",
							read));
					}

					for (int index = 0; index < 8; index++)
					{
						if (buffer[index] == fileMagicData[index])
						{
							continue;
						}

						throw new Exception(String.Format("Invalid file header (expecting 0x{0:X}, read 0x{1:X} at index {2})",
							fileMagicData[index], buffer[index], index));
					}

					ushort encryptedLength = inputFileReader.ReadUInt16();

					if (encryptedLength < 1)
					{
						throw new Exception("Length of encrypted data cannot be zero or negative");
					}

					if (buffer.Length < encryptedLength)
					{
						throw new Exception(String.Format("Invalid length of encrypted data (expecting less than {1} bytes, got {0})",
							encryptedLength, buffer.Length));
					}

					if ((read = inputFileReader.Read(buffer, 0, (int)encryptedLength)) != encryptedLength)
					{
						throw new Exception(String.Format("Unable to read the encrypted data (only read {0} bytes, expecting {1})",
							read, encryptedLength));
					}

					bool result = Advapi.CryptAcquireContext(out provider, container,
						CryptProviderNames.MS_ENH_RSA_AES_PROV, CryptProviderType.PROV_RSA_AES,
						CryptAcquireContextFlags.CRYPT_NEWKEYSET);

					if (result != true)
					{
						throw new Exception("Failed to create a new key set");
					}

					result = Advapi.CryptImportKey(provider, aesKeyData, (uint)aesKeyData.Length,
						IntPtr.Zero, 0, out cryptKey);

					if (result != true)
					{
						throw new Exception("Failed to import the key");
					}

					uint decryptedLength = encryptedLength;

					result = Advapi.CryptDecrypt(cryptKey, IntPtr.Zero, true, CryptOtherFlags.CRYPT_OAEP,
						buffer, out decryptedLength);

					if (result == false)
					{
						throw new Exception("Failed to decrypt the data");
					}

					Console.WriteLine(Encoding.Unicode.GetString(buffer, 0, (int)decryptedLength));
				}
			}
			catch (Exception ex)
			{
				Console.WriteLine(ex);
			}
			finally
			{
				if (cryptKey != IntPtr.Zero && Advapi.CryptDestroyKey(cryptKey) == false)
				{
					Console.WriteLine("Warning: Failed to destroy the cryptographic key");
				}

				if (provider != IntPtr.Zero)
				{
					if (Advapi.CryptReleaseContext(provider, 0) == false)
					{
						Console.WriteLine("Warning: Failed to release the cryptographic context");
					}

					// As per MSDN documentation, we don't need to release the
					// container when calling with CRYPT_DELETEKEYSET.
					if (Advapi.CryptAcquireContext(out provider, container,
							CryptProviderNames.MS_ENH_RSA_AES_PROV,
							CryptProviderType.PROV_RSA_AES,
							CryptAcquireContextFlags.CRYPT_DELETEKEYSET) == false)
					{
						Console.WriteLine("Warning: Failed to delete the created key set");
					}
				}

				if (inputFileReader != null)
				{
					inputFileReader.Close();
				}
			}
		}
	}
}
