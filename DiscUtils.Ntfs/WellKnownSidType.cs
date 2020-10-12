using System;
using System.Runtime.InteropServices;

namespace DiscUtils.Ntfs
{
	[ComVisible(false)]
	public enum WellKnownSidType
	{
		/// <summary>Indicates a null SID.</summary>
		NullSid = 0,

		/// <summary>Indicates a SID that matches everyone.</summary>
		WorldSid = 1,

		/// <summary>Indicates a local SID.</summary>
		LocalSid = 2,

		/// <summary>Indicates a SID that matches the owner or creator of an object.</summary>
		CreatorOwnerSid = 3,

		/// <summary>Indicates a SID that matches the creator group of an object.</summary>
		CreatorGroupSid = 4,

		/// <summary>Indicates a creator owner server SID.</summary>
		CreatorOwnerServerSid = 5,

		/// <summary>Indicates a creator group server SID.</summary>
		CreatorGroupServerSid = 6,

		/// <summary>Indicates a SID for the Windows NT authority account.</summary>
		NTAuthoritySid = 7,

		/// <summary>Indicates a SID for a dial-up account.</summary>
		DialupSid = 8,

		/// <summary>Indicates a SID for a network account. This SID is added to the process of a token when it logs on across a network.</summary>
		NetworkSid = 9,

		/// <summary>Indicates a SID for a batch process. This SID is added to the process of a token when it logs on as a batch job.</summary>
		BatchSid = 10,

		/// <summary>Indicates a SID for an interactive account. This SID is added to the process of a token when it logs on interactively.</summary>
		InteractiveSid = 11,

		/// <summary>Indicates a SID for a service. This SID is added to the process of a token when it logs on as a service.</summary>
		ServiceSid = 12,

		/// <summary>Indicates a SID for the anonymous account.</summary>
		AnonymousSid = 13,

		/// <summary>Indicates a proxy SID.</summary>
		ProxySid = 14,

		/// <summary>Indicates a SID for an enterprise controller.</summary>
		EnterpriseControllersSid = 15,

		/// <summary>Indicates a SID for self.</summary>
		SelfSid = 16,

		/// <summary>Indicates a SID that matches any authenticated user.</summary>
		AuthenticatedUserSid = 17,

		/// <summary>Indicates a SID for restricted code.</summary>
		RestrictedCodeSid = 18,

		/// <summary>Indicates a SID that matches a terminal server account.</summary>
		TerminalServerSid = 19,

		/// <summary>Indicates a SID that matches remote logons.</summary>
		RemoteLogonIdSid = 20,

		/// <summary>Indicates a SID that matches logon IDs.</summary>
		LogonIdsSid = 21,

		/// <summary>Indicates a SID that matches the local system.</summary>
		LocalSystemSid = 22,

		/// <summary>Indicates a SID that matches a local service.</summary>
		LocalServiceSid = 23,

		/// <summary>Indicates a SID that matches a network service.</summary>
		NetworkServiceSid = 24,

		/// <summary>Indicates a SID that matches the domain account.</summary>
		BuiltinDomainSid = 25,

		/// <summary>Indicates a SID that matches the administrator group.</summary>
		BuiltinAdministratorsSid = 26,

		/// <summary>Indicates a SID that matches built-in user accounts.</summary>
		BuiltinUsersSid = 27,

		/// <summary>Indicates a SID that matches the guest account.</summary>
		BuiltinGuestsSid = 28,

		/// <summary>Indicates a SID that matches the power users group.</summary>
		BuiltinPowerUsersSid = 29,

		/// <summary>Indicates a SID that matches the account operators account.</summary>
		BuiltinAccountOperatorsSid = 30,

		/// <summary>Indicates a SID that matches the system operators group.</summary>
		BuiltinSystemOperatorsSid = 31,

		/// <summary>Indicates a SID that matches the print operators group.</summary>
		BuiltinPrintOperatorsSid = 32,

		/// <summary>Indicates a SID that matches the backup operators group.</summary>
		BuiltinBackupOperatorsSid = 33,

		/// <summary>Indicates a SID that matches the replicator account.</summary>
		BuiltinReplicatorSid = 34,

		/// <summary>Indicates a SID that matches pre-Windows 2000 compatible accounts.</summary>
		BuiltinPreWindows2000CompatibleAccessSid = 35,

		/// <summary>Indicates a SID that matches remote desktop users.</summary>
		BuiltinRemoteDesktopUsersSid = 36,

		/// <summary>Indicates a SID that matches the network operators group.</summary>
		BuiltinNetworkConfigurationOperatorsSid = 37,

		/// <summary>Indicates a SID that matches the account administrator's account.</summary>
		AccountAdministratorSid = 38,

		/// <summary>Indicates a SID that matches the account guest group.</summary>
		AccountGuestSid = 39,

		/// <summary>Indicates a SID that matches account Kerberos target group.</summary>
		AccountKrbtgtSid = 40,

		/// <summary>Indicates a SID that matches the account domain administrator group.</summary>
		AccountDomainAdminsSid = 41,

		/// <summary>Indicates a SID that matches the account domain users group.</summary>
		AccountDomainUsersSid = 42,

		/// <summary>Indicates a SID that matches the account domain guests group.</summary>
		AccountDomainGuestsSid = 43,

		/// <summary>Indicates a SID that matches the account computer group.</summary>
		AccountComputersSid = 44,

		/// <summary>Indicates a SID that matches the account controller group.</summary>
		AccountControllersSid = 45,

		/// <summary>Indicates a SID that matches the certificate administrators group.</summary>
		AccountCertAdminsSid = 46,

		/// <summary>Indicates a SID that matches the schema administrators group.</summary>
		AccountSchemaAdminsSid = 47,

		/// <summary>Indicates a SID that matches the enterprise administrators group.</summary>
		AccountEnterpriseAdminsSid = 48,

		/// <summary>Indicates a SID that matches the policy administrators group.</summary>
		AccountPolicyAdminsSid = 49,

		/// <summary>Indicates a SID that matches the RAS and IAS server account.</summary>
		AccountRasAndIasServersSid = 50,

		/// <summary>Indicates a SID present when the Microsoft NTLM authentication package authenticated the client.</summary>
		NtlmAuthenticationSid = 51,

		/// <summary>Indicates a SID present when the Microsoft Digest authentication package authenticated the client.</summary>
		DigestAuthenticationSid = 52,

		/// <summary>Indicates a SID present when the Secure Channel (SSL/TLS) authentication package authenticated the client.</summary>
		SChannelAuthenticationSid = 53,

		/// <summary>Indicates a SID present when the user authenticated from within the forest or across a trust that does not have the selective authentication option enabled. If this SID is present, then <see cref="OtherOrganizationSid"/> cannot be present.</summary>
		ThisOrganizationSid = 54,

		/// <summary>Indicates a SID present when the user authenticated across a forest with the selective authentication option enabled. If this SID is present, then <see cref="ThisOrganizationSid"/> cannot be present.</summary>
		OtherOrganizationSid = 55,

		/// <summary>Indicates a SID that allows a user to create incoming forest trusts. It is added to the token of users who are a member of the Incoming Forest Trust Builders built-in group in the root domain of the forest.</summary>
		BuiltinIncomingForestTrustBuildersSid = 56,

		/// <summary>Indicates a SID that matches the performance monitor user group.</summary>
		BuiltinPerformanceMonitoringUsersSid = 57,

		/// <summary>Indicates a SID that matches the performance log user group.</summary>
		BuiltinPerformanceLoggingUsersSid = 58,

		/// <summary>Indicates a SID that matches the Windows Authorization Access group.</summary>
		BuiltinAuthorizationAccessSid = 59,

		/// <summary>Indicates a SID is present in a server that can issue terminal server licenses.</summary>
		WinBuiltinTerminalServerLicenseServersSid = 60,

		[Obsolete("This member has been depcreated and is only maintained for backwards compatability. WellKnownSidType values greater than MaxDefined may be defined in future releases.")]
		MaxDefined = WinBuiltinTerminalServerLicenseServersSid,

		/// <summary>Indicates a SID that matches the distributed COM user group.</summary>
		WinBuiltinDCOMUsersSid = 61,

		/// <summary>Indicates a SID that matches the Internet built-in user group.</summary>
		WinBuiltinIUsersSid = 62,

		/// <summary>Indicates a SID that matches the Internet user group.</summary>
		WinIUserSid = 63,

		/// <summary>Indicates a SID that allows a user to use cryptographic operations. It is added to the token of users who are a member of the CryptoOperators built-in group. </summary>
		WinBuiltinCryptoOperatorsSid = 64,

		/// <summary>Indicates a SID that matches an untrusted label.</summary>
		WinUntrustedLabelSid = 65,

		/// <summary>Indicates a SID that matches an low level of trust label.</summary>
		WinLowLabelSid = 66,

		/// <summary>Indicates a SID that matches an medium level of trust label.</summary>
		WinMediumLabelSid = 67,

		/// <summary>Indicates a SID that matches a high level of trust label.</summary>
		WinHighLabelSid = 68,

		/// <summary>Indicates a SID that matches a system label.</summary>
		WinSystemLabelSid = 69,

		/// <summary>Indicates a SID that matches a write restricted code group.</summary>
		WinWriteRestrictedCodeSid = 70,

		/// <summary>Indicates a SID that matches a creator and owner rights group.</summary>
		WinCreatorOwnerRightsSid = 71,

		/// <summary>Indicates a SID that matches a cacheable principals group.</summary>
		WinCacheablePrincipalsGroupSid = 72,

		/// <summary>Indicates a SID that matches a non-cacheable principals group.</summary>
		WinNonCacheablePrincipalsGroupSid = 73,

		/// <summary>Indicates a SID that matches an enterprise wide read-only controllers group.</summary>
		WinEnterpriseReadonlyControllersSid = 74,

		/// <summary>Indicates a SID that matches an account read-only controllers group.</summary>
		WinAccountReadonlyControllersSid = 75,

		/// <summary>Indicates a SID that matches an event log readers group.</summary>
		WinBuiltinEventLogReadersGroup = 76,

		/// <summary>Indicates a SID that matches a read-only enterprise domain controller.</summary>
		WinNewEnterpriseReadonlyControllersSid = 77,

		/// <summary>Indicates a SID that matches the built-in DCOM certification services access group.</summary>
		WinBuiltinCertSvcDComAccessGroup = 78,

		/// <summary>Indicates a SID that matches the medium plus integrity label.</summary>
		WinMediumPlusLabelSid = 79,

		/// <summary>Indicates a SID that matches a local logon group.</summary>
		WinLocalLogonSid = 80,

		/// <summary>Indicates a SID that matches a console logon group.</summary>
		WinConsoleLogonSid = 81,

		/// <summary>Indicates a SID that matches a certificate for the given organization.</summary>
		WinThisOrganizationCertificateSid = 82,

		/// <summary>Indicates a SID that matches the application package authority.</summary>
		WinApplicationPackageAuthoritySid = 83,

		/// <summary>Indicates a SID that applies to all app containers.</summary>
		WinBuiltinAnyPackageSid = 84,

		/// <summary>Indicates a SID of Internet client capability for app containers.</summary>
		WinCapabilityInternetClientSid = 85,

		/// <summary>Indicates a SID of Internet client and server capability for app containers.</summary>
		WinCapabilityInternetClientServerSid = 86,

		/// <summary>Indicates a SID of private network client and server capability for app containers.</summary>
		WinCapabilityPrivateNetworkClientServerSid = 87,

		/// <summary>Indicates a SID for pictures library capability for app containers.</summary>
		WinCapabilityPicturesLibrarySid = 88,

		/// <summary>Indicates a SID for videos library capability for app containers.</summary>
		WinCapabilityVideosLibrarySid = 89,

		/// <summary>Indicates a SID for music library capability for app containers.</summary>
		WinCapabilityMusicLibrarySid = 90,

		/// <summary>Indicates a SID for documents library capability for app containers.</summary>
		WinCapabilityDocumentsLibrarySid = 91,

		/// <summary>Indicates a SID for shared user certificates capability for app containers.</summary>
		WinCapabilitySharedUserCertificatesSid = 92,

		/// <summary>Indicates a SID for Windows credentials capability for app containers.</summary>
		WinCapabilityEnterpriseAuthenticationSid = 93,

		/// <summary>Indicates a SID for removable storage capability for app containers.</summary>
		WinCapabilityRemovableStorageSid = 94
	}
}