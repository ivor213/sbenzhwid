using System;
using System.Drawing;
using System.Drawing.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Net.Http;
using System.Text;
using Newtonsoft.Json;
using System.Management;
using System.Security.Cryptography;

namespace sbenz_loader
{
    public partial class LoginForm : Form
    {
        private bool dragging = false;
        private Point dragCursorPoint;
        private Point dragFormPoint;
        private PrivateFontCollection fonts = new PrivateFontCollection();
        private int currentUserId = 0;
        private string currentProduct = null;
        private DateTime? currentExpiresAt = null;

        // Shared HttpClientHandler and HttpClient for session cookies
        private readonly HttpClientHandler handler = new HttpClientHandler { UseCookies = true };
        private readonly HttpClient client;

        public LoginForm()
        {
            InitializeComponent();
            this.FormBorderStyle = FormBorderStyle.None;
            this.DoubleBuffered = true;
            client = new HttpClient(handler);
            client.BaseAddress = new Uri("http://localhost:3000");
        }

        // Custom window dragging
        private void panelContainer_MouseDown(object sender, MouseEventArgs e)
        {
            dragging = true;
            dragCursorPoint = Cursor.Position;
            dragFormPoint = this.Location;
        }
        private void panelContainer_MouseMove(object sender, MouseEventArgs e)
        {
            if (dragging)
            {
                Point diff = Point.Subtract(Cursor.Position, new Size(dragCursorPoint));
                this.Location = Point.Add(dragFormPoint, new Size(diff));
            }
        }
        private void panelContainer_MouseUp(object sender, MouseEventArgs e)
        {
            dragging = false;
        }

        // Add drag handlers for the top bar
        private void topBarPanel_MouseDown(object sender, MouseEventArgs e)
        {
            dragging = true;
            dragCursorPoint = Cursor.Position;
            dragFormPoint = this.Location;
        }
        private void topBarPanel_MouseMove(object sender, MouseEventArgs e)
        {
            if (dragging)
            {
                Point diff = Point.Subtract(Cursor.Position, new Size(dragCursorPoint));
                this.Location = Point.Add(dragFormPoint, new Size(diff));
            }
        }
        private void topBarPanel_MouseUp(object sender, MouseEventArgs e)
        {
            dragging = false;
        }

        private void buttonExit_Click(object sender, EventArgs e)
        {
            this.Close();
        }

        private async void buttonSubmit_Click(object sender, EventArgs e)
        {
            string username = textBoxUsername.Text.Trim();
            string password = textBoxPassword.Text;
            bool remember = checkBoxRemember.Checked;

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                labelStatus.ForeColor = Color.Red;
                labelStatus.Text = "Please enter both username and password.";
                return;
            }

            labelStatus.ForeColor = Color.Gainsboro;
            labelStatus.Text = "Logging in...";
            try
            {
                var loginData = new
                {
                    username = username,
                    password = password,
                    remember = remember
                };
                var json = JsonConvert.SerializeObject(loginData);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                var response = await client.PostAsync("/api/login", content);
                var responseString = await response.Content.ReadAsStringAsync();
                dynamic result = JsonConvert.DeserializeObject(responseString);
                if (result.success == true)
                {
                    await CheckUserProduct();
                }
                else
                {
                    string msg = result.message != null ? (string)result.message : "Login failed.";
                    if (msg.ToLower().Contains("suspend") || msg.ToLower().Contains("ban"))
                    {
                        MessageBox.Show(msg, "$benz.club loader - Banned", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        labelStatus.Text = "";
                    }
                    else
                    {
                        labelStatus.ForeColor = Color.Red;
                        labelStatus.Text = msg;
                    }
                }
            }
            catch (Exception ex)
            {
                labelStatus.ForeColor = Color.Red;
                labelStatus.Text = "Error connecting to server: " + ex.Message;
            }
        }

        private async Task CheckUserProduct()
        {
            try
            {
                var response = await client.GetAsync("/api/user-product");
                var responseString = await response.Content.ReadAsStringAsync();
                dynamic result = JsonConvert.DeserializeObject(responseString);
                if (result.success == true && result.product != null)
                {
                    currentProduct = (string)result.product;
                    currentExpiresAt = null;
                    if (result.expiresAt != null)
                    {
                        DateTime expires;
                        if (DateTime.TryParse((string)result.expiresAt, out expires))
                            currentExpiresAt = expires.ToLocalTime();
                    }
                    ShowProductLoadPage();
                }
                else
                {
                    panelContainer.Visible = false;
                    panelKeyActivation.Visible = true;
                    labelKeyStatus.Text = "";
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error checking user product: " + ex.Message, "$benz.club loader");
            }
        }

        private string GetHWID()
        {
            try
            {
                string drive = Environment.GetFolderPath(Environment.SpecialFolder.System).Substring(0, 1);
                string serial = "";
                using (var searcher = new ManagementObjectSearcher($"SELECT VolumeSerialNumber FROM Win32_LogicalDisk WHERE DeviceID = '{drive}:'"))
                {
                    foreach (ManagementObject disk in searcher.Get())
                    {
                        serial = disk["VolumeSerialNumber"].ToString();
                        break;
                    }
                }
                string raw = serial + Environment.MachineName;
                using (SHA256 sha = SHA256.Create())
                {
                    byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(raw));
                    return BitConverter.ToString(hash).Replace("-", "");
                }
            }
            catch
            {
                return Environment.MachineName;
            }
        }

        private async void buttonActivate_Click(object sender, EventArgs e)
        {
            string key = textBoxKey.Text.Trim();
            if (string.IsNullOrEmpty(key))
            {
                labelKeyStatus.ForeColor = Color.Red;
                labelKeyStatus.Text = "Please enter a license key.";
                return;
            }
            labelKeyStatus.ForeColor = Color.Gainsboro;
            labelKeyStatus.Text = "Validating key...";
            try
            {
                string hwid = GetHWID();
                var data = new { licenseKey = key, hwid = hwid };
                var json = JsonConvert.SerializeObject(data);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                var response = await client.PostAsync("/api/activate-license", content);
                var responseString = await response.Content.ReadAsStringAsync();
                dynamic result = JsonConvert.DeserializeObject(responseString);
                if (result.success == true && result.product != null)
                {
                    currentProduct = (string)result.product;
                    ShowProductLoadPage();
                }
                else
                {
                    labelKeyStatus.ForeColor = Color.Red;
                    labelKeyStatus.Text = result.message != null ? (string)result.message : "Invalid or already used key.";
                }
            }
            catch (Exception ex)
            {
                labelKeyStatus.ForeColor = Color.Red;
                labelKeyStatus.Text = "Error connecting to server: " + ex.Message;
            }
        }

        private void ShowProductLoadPage()
        {
            panelContainer.Visible = false;
            panelKeyActivation.Visible = false;
            panelProductLoad.Visible = true;
            labelProductName.Text = $"Product: {currentProduct}";
            if (currentExpiresAt.HasValue)
            {
                TimeSpan remaining = currentExpiresAt.Value - DateTime.Now;
                int days = (int)remaining.TotalDays;
                int hours = remaining.Hours;
                if (remaining.TotalSeconds > 0)
                    labelTimeRemaining.Text = $"Time remaining: {days}d {hours}h";
                else
                    labelTimeRemaining.Text = "Time remaining: expired";
            }
            else
            {
                labelTimeRemaining.Text = "Time remaining: --";
            }
        }

        private void buttonLoadProduct_Click(object sender, EventArgs e)
        {
            MessageBox.Show($"Loading {currentProduct}... (EXE launch placeholder)", "$benz.club loader");
            // TODO: Launch the product's EXE here
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            // Draw a 1px light gray border around the window, similar to default Windows border
            using (Pen pen = new Pen(Color.LightGray, 1))
            {
                e.Graphics.DrawRectangle(pen, 0, 0, this.ClientSize.Width - 1, this.ClientSize.Height - 1);
            }
        }
    }
}

// NOTE: For best results, copy Monoton-Regular.ttf to your output directory (e.g., bin/Debug/netX.X/) 