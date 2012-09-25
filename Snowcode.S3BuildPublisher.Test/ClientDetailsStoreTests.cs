using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;
using System.Security.Principal;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using NUnit.Framework;
using Snowcode.S3BuildPublisher.Client;

namespace Snowcode.S3BuildPublisher.Test
{
    [TestFixture]
    public class ClientDetailsStoreTests
    {
        private const string DefaultTestRegistrySubKey = "Software\\SnowCode\\S3BuildPublisher\\Tests";

        [SetUp]
        public void Setup()
        {
            if (Registry.CurrentUser.OpenSubKey(DefaultTestRegistrySubKey) != null)
            {
                Registry.CurrentUser.DeleteSubKey(DefaultTestRegistrySubKey);
            }
        }

        [TearDown]
        public void TearDown()
        {
            if (Registry.CurrentUser.OpenSubKey(DefaultTestRegistrySubKey) != null)
            {
                Registry.CurrentUser.DeleteSubKey(DefaultTestRegistrySubKey);
            }
        }

        [Test]
        public void SaveAndLoadClientDetails_AreCorrectlyStored()
        {
            const string containerName = "S3BuildPublisher.TestContainer.ClientDetailsStore";
            var clientDetails = new AwsClientDetails
                                    {
                                        AwsAccessKeyId = "AwsAccessKeyId",
                                        AwsSecretAccessKey = "AwsSecretAccessKey"
                                    };

            var store = new ClientDetailsStore(DefaultTestRegistrySubKey);

            store.Save(containerName, clientDetails);
			RunAsUser(".", "reports", "reports", () =>
			                                     	{
														AwsClientDetails actual = store.Load(containerName);

														Assert.AreEqual(clientDetails.AwsAccessKeyId, actual.AwsAccessKeyId, "AwsAccessKeyId");
														Assert.AreEqual(clientDetails.AwsSecretAccessKey, actual.AwsSecretAccessKey, "AwsSecretAccessKey");
			                                     	});
        }

		[Test]
		public static void VerifyImpersonation()
		{
			RunAsUser(".", "reports", "reports", () => { });
		}

    	private static void RunAsUser(string domain, string username, string password, Action work)
    	{
    		SafeTokenHandle safeTokenHandle;
    		try
    		{
    			const int LOGON32_PROVIDER_DEFAULT = 0;
    			//This parameter causes LogonUser to create a primary token. 
    			const int LOGON32_LOGON_INTERACTIVE = 2;

    			// Call LogonUser to obtain a handle to an access token. 
    			bool returnValue = ImpersonationAPI.LogonUser(username, domain, password,
    			                                              LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
    			                                              out safeTokenHandle);

//    			Console.WriteLine("LogonUser called.");

    			if (false == returnValue)
    			{
    				int ret = Marshal.GetLastWin32Error();
//    				Console.WriteLine("LogonUser failed with error code : {0}", ret);
    				throw new System.ComponentModel.Win32Exception(ret);
    			}
    			using (safeTokenHandle)
    			{
//    				Console.WriteLine("Did LogonUser Succeed? " + (returnValue ? "Yes" : "No"));
//    				Console.WriteLine("Value of Windows NT token: " + safeTokenHandle);

    				// Check the identity.
//    				Console.WriteLine("Before impersonation: " + WindowsIdentity.GetCurrent().Name);
    				// Use the token handle returned by LogonUser. 
    				using (WindowsImpersonationContext impersonatedUser = WindowsIdentity.Impersonate(safeTokenHandle.DangerousGetHandle()))
    				{
    					// Check the identity.
//    					Console.WriteLine("After impersonation: " + WindowsIdentity.GetCurrent().Name);
    					work();
    				}
    				// Releasing the context object stops the impersonation 
    				// Check the identity.
//    				Console.WriteLine("After closing the context: " + WindowsIdentity.GetCurrent().Name);
    			}
    		}
    		catch (Exception ex)
    		{
    			Console.WriteLine("Exception occurred. " + ex.ToString());
    			throw;
    		}
    	}
    }
}

public class ImpersonationAPI
{
	[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
	public static extern bool LogonUser(String lpszUsername, String lpszDomain, String lpszPassword,
		int dwLogonType, int dwLogonProvider, out SafeTokenHandle phToken);

	[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
	public extern static bool CloseHandle(IntPtr handle);
	
}
public sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
{
	private SafeTokenHandle()
		: base(true)
	{
	}

	[DllImport("kernel32.dll")]
	[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
	[SuppressUnmanagedCodeSecurity]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool CloseHandle(IntPtr handle);

	protected override bool ReleaseHandle()
	{
		return CloseHandle(handle);
	}
}
