using System.Security.Principal;

namespace sbenz_loader
{
    internal static class Program
    {
        /// <summary>
        ///  The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            // Check if running as administrator
            if (!IsRunAsAdministrator())
            {
                // Restart the application with admin privileges
                var processInfo = new System.Diagnostics.ProcessStartInfo(Application.ExecutablePath);
                processInfo.UseShellExecute = true;
                processInfo.Verb = "runas"; // This will prompt for admin privileges
                
                try
                {
                    System.Diagnostics.Process.Start(processInfo);
                }
                catch (System.ComponentModel.Win32Exception)
                {
                    // User cancelled the UAC prompt
                    MessageBox.Show("This application requires administrator privileges to run.", 
                        "Administrator Required", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
                
                return; // Exit the current instance
            }

            // To customize application configuration such as set high DPI settings or default font,
            // see https://aka.ms/applicationconfiguration.
            ApplicationConfiguration.Initialize();
            Application.Run(new LoginForm());
        }

        private static bool IsRunAsAdministrator()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
    }
}