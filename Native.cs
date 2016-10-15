using System;
using System.Runtime.InteropServices;

namespace HpqPswdD.Native
{
	[Flags]
	public enum CryptAcquireContextFlags : uint
	{
		CRYPT_NEWKEYSET = 0x00000008,
		CRYPT_DELETEKEYSET = 0x00000010,
		CRYPT_MACHINE_KEYSET = 0x00000020,
		CRYPT_SILENT = 0x00000040,
		CRYPT_DEFAULT_CONTAINER_OPTIONAL = 0x00000080,
		CRYPT_VERIFYCONTEXT = 0xF0000000
	}

	[Flags]
	public enum CryptProviderType : uint
	{
		PROV_RSA_FULL = 0x01,
		PROV_RSA_SIG = 0x02,
		PROV_DSS = 0x03,
		PROV_FORTEZZA = 0x04,
		PROV_MS_EXCHANGE = 0x05,
		PROV_SSL = 0x06,
		PROV_RSA_SCHANNEL = 0x0C,
		PROV_DSS_DH = 0x0D,
		PROV_EC_ECDSA_SIG = 0x0E,
		PROV_EC_ECNRA_SIG = 0x0F,
		PROV_EC_ECDSA_FULL = 0x10,
		PROV_EC_ECNRA_FULL = 0x11,
		PROV_DH_SCHANNEL = 0x12,
		PROV_SPYRUS_LYNKS = 0x14,
		PROV_RNG = 0x15,
		PROV_INTEL_SEC = 0x16, 
		PROV_REPLACE_OWF = 0x17, 
		PROV_RSA_AES = 0x18
	}

	[Flags]
	public enum CryptOtherFlags : uint
	{
		CRYPT_NONE = 0x0000,
		CRYPT_EXPORTABLE = 0x0001,
		CRYPT_USER_PROTECTED = 0x0002,
		CRYPT_NO_SALT = 0x0010,
		CRYPT_OAEP = 0x0040,
		CRYPT_IPSEC_HMAC_KEY = 0x0100
	}

	public struct CryptProviderNames
	{
		public static readonly string MS_ENH_RSA_AES_PROV = "Microsoft Enhanced RSA and AES Cryptographic Provider";
	}

	public static class Advapi
	{
		[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		[return : MarshalAs(UnmanagedType.Bool)]
		public static extern bool CryptAcquireContext(
			out IntPtr prov,
			[MarshalAs(UnmanagedType.LPTStr)]
			string container,
			[MarshalAs(UnmanagedType.LPTStr)]
			string provider,
			[MarshalAs(UnmanagedType.U4)]
			CryptProviderType provType,
			[MarshalAs(UnmanagedType.U4)]
			CryptAcquireContextFlags flags);

		[DllImport("advapi32.dll", SetLastError = true)]
		[return : MarshalAs(UnmanagedType.Bool)]
		public static extern bool CryptReleaseContext(
			IntPtr prov,
			[MarshalAs(UnmanagedType.U4)]
			uint flags);

		[DllImport("advapi32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool CryptImportKey(
			IntPtr prov,
			byte[] keyData,
			[MarshalAs(UnmanagedType.U4)]
			uint dataLen,
			IntPtr pubKey,
			[MarshalAs(UnmanagedType.U4)]
			CryptOtherFlags flags,
			out IntPtr key);
			
		[DllImport("advapi32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool CryptDestroyKey(
			IntPtr key);

		[DllImport("advapi32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool CryptDecrypt(
			IntPtr key,
			IntPtr hash,
			[MarshalAs(UnmanagedType.Bool)]
			bool final,
			[MarshalAs(UnmanagedType.U4)]
			CryptOtherFlags flags,
			byte[] data,
			[MarshalAs(UnmanagedType.U4)]
			out uint dataLen);
			
		[DllImport("advapi32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool CryptEncrypt(
			IntPtr key,
			IntPtr hash,
			[MarshalAs(UnmanagedType.Bool)]
			bool final,
			[MarshalAs(UnmanagedType.U4)]
			CryptOtherFlags flags,
			byte[] data,
			[MarshalAs(UnmanagedType.U4)]
			out uint dataLen,
			[MarshalAs(UnmanagedType.U4)]
			uint bufLen);
	}
}
