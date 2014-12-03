/*
 * InexorablePoSH
 * Description: Application to load and run powershell code via the .NET assemblies
 * License: 3-Clause BSD License. See Veil PowerTools Project
 * 
 * This application is part of Veil PowerTools, a collection of offensive PowerShell 
 * capabilities. Hope they help! 
 */

using System;
using System.IO;
using System.Resources;
using System.Collections.Generic;
using System.Linq;
using System.Text;

//Adding libraries for powershell stuff
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;


namespace InexorablePoSH
{
    class Program
    {
        static void Main(string[] args)
        {
            //Init stuff
            Runspace runspace = RunspaceFactory.CreateRunspace();
            runspace.Open();
            RunspaceInvoke scriptInvoker = new RunspaceInvoke(runspace);
            Pipeline pipeline = runspace.CreatePipeline();

            //Add commands
            string script = Properties.Resources.ResourceManager.GetString("Script");
            pipeline.Commands.AddScript(script);

            //Prep PS for string output and invoke
            pipeline.Commands.Add("Out-String");
            Collection<PSObject> results = pipeline.Invoke();
            runspace.Close();

            //Convert records to strings
            StringBuilder stringBuilder = new StringBuilder();
            foreach (PSObject obj in results)
            {
                stringBuilder.AppendLine(obj.ToString());
            }
            Console.Write(stringBuilder.ToString());
        }
    }
}
