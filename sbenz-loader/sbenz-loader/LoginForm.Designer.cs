namespace sbenz_loader
{
    partial class LoginForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            panelContainer = new Panel();
            buttonExit = new Button();
            labelUsername = new Label();
            textBoxUsername = new TextBox();
            labelPassword = new Label();
            textBoxPassword = new TextBox();
            checkBoxRemember = new CheckBox();
            buttonSubmit = new Button();
            labelStatus = new Label();
            topBarPanel = new Panel();
            topBarLabel = new Label();
            panelKeyActivation = new Panel();
            labelKeyPrompt = new Label();
            textBoxKey = new TextBox();
            buttonActivate = new Button();
            labelKeyStatus = new Label();
            panelContainer.SuspendLayout();
            topBarPanel.SuspendLayout();
            SuspendLayout();
            // 
            // panelContainer
            // 
            panelContainer.BackColor = Color.FromArgb(30, 30, 30);
            panelContainer.Controls.Add(labelUsername);
            panelContainer.Controls.Add(textBoxUsername);
            panelContainer.Controls.Add(labelPassword);
            panelContainer.Controls.Add(textBoxPassword);
            panelContainer.Controls.Add(checkBoxRemember);
            panelContainer.Controls.Add(buttonSubmit);
            panelContainer.Controls.Add(labelStatus);
            panelContainer.Location = new Point(1, 1);
            panelContainer.Name = "panelContainer";
            panelContainer.Size = new Size(218, 208);
            panelContainer.TabIndex = 0;
            panelContainer.MouseDown += panelContainer_MouseDown;
            panelContainer.MouseMove += panelContainer_MouseMove;
            panelContainer.MouseUp += panelContainer_MouseUp;
            // 
            // buttonExit
            // 
            buttonExit.BackColor = Color.Transparent;
            buttonExit.FlatAppearance.BorderSize = 0;
            buttonExit.FlatAppearance.MouseOverBackColor = Color.FromArgb(40, 255, 0, 0);
            buttonExit.FlatStyle = FlatStyle.Flat;
            buttonExit.Font = new Font("Consolas", 7F, FontStyle.Bold);
            buttonExit.ForeColor = Color.Red;
            buttonExit.Location = new Point(196, 3);
            buttonExit.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right;
            buttonExit.Name = "buttonExit";
            buttonExit.Size = new Size(18, 18);
            buttonExit.TabIndex = 101;
            buttonExit.Text = "⨉";
            buttonExit.UseVisualStyleBackColor = true;
            buttonExit.Click += buttonExit_Click;
            // 
            // labelUsername
            // 
            labelUsername.AutoSize = true;
            labelUsername.Font = new Font("Consolas", 10F);
            labelUsername.ForeColor = Color.White;
            labelUsername.Location = new Point(20, 40);
            labelUsername.Name = "labelUsername";
            labelUsername.Size = new Size(96, 17);
            labelUsername.TabIndex = 0;
            labelUsername.Text = "> username:";
            // 
            // textBoxUsername
            // 
            textBoxUsername.BackColor = Color.Black;
            textBoxUsername.BorderStyle = BorderStyle.FixedSingle;
            textBoxUsername.Font = new Font("Consolas", 10F);
            textBoxUsername.ForeColor = Color.White;
            textBoxUsername.Location = new Point(20, 60);
            textBoxUsername.Name = "textBoxUsername";
            textBoxUsername.Size = new Size(170, 23);
            textBoxUsername.TabIndex = 1;
            // 
            // labelPassword
            // 
            labelPassword.AutoSize = true;
            labelPassword.Font = new Font("Consolas", 10F);
            labelPassword.ForeColor = Color.White;
            labelPassword.Location = new Point(20, 86);
            labelPassword.Name = "labelPassword";
            labelPassword.Size = new Size(96, 17);
            labelPassword.TabIndex = 2;
            labelPassword.Text = "> password:";
            // 
            // textBoxPassword
            // 
            textBoxPassword.BackColor = Color.Black;
            textBoxPassword.BorderStyle = BorderStyle.FixedSingle;
            textBoxPassword.Font = new Font("Consolas", 10F);
            textBoxPassword.ForeColor = Color.White;
            textBoxPassword.Location = new Point(20, 105);
            textBoxPassword.Name = "textBoxPassword";
            textBoxPassword.PasswordChar = '*';
            textBoxPassword.Size = new Size(170, 23);
            textBoxPassword.TabIndex = 3;
            // 
            // checkBoxRemember
            // 
            checkBoxRemember.AutoSize = true;
            checkBoxRemember.Font = new Font("Consolas", 9F);
            checkBoxRemember.ForeColor = Color.Gainsboro;
            checkBoxRemember.Location = new Point(20, 135);
            checkBoxRemember.Name = "checkBoxRemember";
            checkBoxRemember.Size = new Size(103, 18);
            checkBoxRemember.TabIndex = 4;
            checkBoxRemember.Text = "Remember Me";
            checkBoxRemember.UseVisualStyleBackColor = true;
            // 
            // buttonSubmit
            // 
            buttonSubmit.BackColor = Color.Transparent;
            buttonSubmit.FlatAppearance.BorderColor = Color.White;
            buttonSubmit.FlatStyle = FlatStyle.Flat;
            buttonSubmit.Font = new Font("Consolas", 10F);
            buttonSubmit.ForeColor = Color.White;
            buttonSubmit.Location = new Point(20, 160);
            buttonSubmit.Name = "buttonSubmit";
            buttonSubmit.Size = new Size(170, 24);
            buttonSubmit.TabIndex = 5;
            buttonSubmit.Text = "Submit";
            buttonSubmit.UseVisualStyleBackColor = false;
            buttonSubmit.Click += buttonSubmit_Click;
            // 
            // labelStatus
            // 
            labelStatus.AutoSize = true;
            labelStatus.Font = new Font("Consolas", 9F);
            labelStatus.ForeColor = Color.LightGreen;
            labelStatus.Location = new Point(20, 190);
            labelStatus.Name = "labelStatus";
            labelStatus.Size = new Size(0, 14);
            labelStatus.TabIndex = 6;
            // 
            // topBarPanel
            // 
            topBarPanel.BackColor = Color.FromArgb(25, 25, 25);
            topBarPanel.Controls.Add(topBarLabel);
            topBarPanel.Controls.Add(buttonExit);
            topBarPanel.Dock = DockStyle.Top;
            topBarPanel.Location = new Point(0, 0);
            topBarPanel.Margin = new Padding(0);
            topBarPanel.Name = "topBarPanel";
            topBarPanel.Size = new Size(220, 24);
            topBarPanel.TabIndex = 0;
            topBarPanel.MouseDown += topBarPanel_MouseDown;
            topBarPanel.MouseMove += topBarPanel_MouseMove;
            topBarPanel.MouseUp += topBarPanel_MouseUp;
            // 
            // topBarLabel
            // 
            topBarLabel.Dock = System.Windows.Forms.DockStyle.None;
            topBarLabel.Font = new Font("Segoe UI", 9F, FontStyle.Bold);
            topBarLabel.ForeColor = Color.Gainsboro;
            topBarLabel.Location = new System.Drawing.Point(11, 0);
            topBarLabel.Name = "topBarLabel";
            topBarLabel.Size = new System.Drawing.Size(180, 24);
            topBarLabel.TabIndex = 0;
            topBarLabel.Text = "$benz.club loader";
            topBarLabel.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            topBarLabel.MouseDown += topBarPanel_MouseDown;
            topBarLabel.MouseMove += topBarPanel_MouseMove;
            topBarLabel.MouseUp += topBarPanel_MouseUp;
            // 
            // panelKeyActivation
            // 
            panelKeyActivation.BackColor = System.Drawing.Color.FromArgb(30, 30, 30);
            panelKeyActivation.BorderStyle = System.Windows.Forms.BorderStyle.None;
            panelKeyActivation.Location = this.panelContainer.Location;
            panelKeyActivation.Size = this.panelContainer.Size;
            panelKeyActivation.Visible = false;
            panelKeyActivation.Controls.Add(labelKeyPrompt);
            panelKeyActivation.Controls.Add(textBoxKey);
            panelKeyActivation.Controls.Add(buttonActivate);
            panelKeyActivation.Controls.Add(labelKeyStatus);
            // 
            // labelKeyPrompt
            // 
            labelKeyPrompt.Text = "Enter your license key:";
            labelKeyPrompt.ForeColor = System.Drawing.Color.White;
            labelKeyPrompt.Font = new System.Drawing.Font("Consolas", 10F);
            labelKeyPrompt.Location = new System.Drawing.Point(20, 40);
            labelKeyPrompt.Size = new System.Drawing.Size(180, 17);
            // 
            // textBoxKey
            // 
            textBoxKey.BackColor = System.Drawing.Color.Black;
            textBoxKey.ForeColor = System.Drawing.Color.White;
            textBoxKey.Font = new System.Drawing.Font("Consolas", 10F);
            textBoxKey.Location = new System.Drawing.Point(20, 60);
            textBoxKey.Size = new System.Drawing.Size(170, 23);
            // 
            // buttonActivate
            // 
            buttonActivate.Text = "Activate";
            buttonActivate.Font = new System.Drawing.Font("Consolas", 10F);
            buttonActivate.ForeColor = System.Drawing.Color.White;
            buttonActivate.BackColor = System.Drawing.Color.Transparent;
            buttonActivate.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            buttonActivate.FlatAppearance.BorderColor = System.Drawing.Color.White;
            buttonActivate.Location = new System.Drawing.Point(20, 100);
            buttonActivate.Size = new System.Drawing.Size(170, 24);
            buttonActivate.Click += new System.EventHandler(this.buttonActivate_Click);
            // 
            // labelKeyStatus
            // 
            labelKeyStatus.ForeColor = System.Drawing.Color.LightGreen;
            labelKeyStatus.Font = new System.Drawing.Font("Consolas", 9F);
            labelKeyStatus.Location = new System.Drawing.Point(20, 140);
            labelKeyStatus.Size = new System.Drawing.Size(170, 20);
            // 
            // LoginForm
            // 
            AutoScaleDimensions = new SizeF(7F, 14F);
            AutoScaleMode = AutoScaleMode.Font;
            BackColor = SystemColors.Control;
            ClientSize = new Size(220, 210);
            Controls.Add(topBarPanel);
            Controls.Add(panelContainer);
            Controls.Add(panelKeyActivation);
            Font = new Font("Consolas", 9F);
            FormBorderStyle = FormBorderStyle.None;
            MaximizeBox = false;
            Name = "LoginForm";
            StartPosition = FormStartPosition.CenterScreen;
            Text = "$benz.club Login";
            panelContainer.ResumeLayout(false);
            panelContainer.PerformLayout();
            topBarPanel.ResumeLayout(false);
            ResumeLayout(false);
            // Add product load panel
            this.panelProductLoad = new System.Windows.Forms.Panel();
            this.panelProductLoad.BackColor = System.Drawing.Color.FromArgb(30, 30, 30);
            this.panelProductLoad.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.panelProductLoad.Location = this.panelContainer.Location;
            this.panelProductLoad.Size = this.panelContainer.Size;
            this.panelProductLoad.Visible = false;
            // Add controls to product load panel
            this.labelProductName = new System.Windows.Forms.Label();
            this.labelProductName.Text = "Product: ";
            this.labelProductName.ForeColor = System.Drawing.Color.White;
            this.labelProductName.Font = new System.Drawing.Font("Consolas", 10F);
            this.labelProductName.Location = new System.Drawing.Point(20, 40);
            this.labelProductName.Size = new System.Drawing.Size(180, 17);
            this.buttonLoadProduct = new System.Windows.Forms.Button();
            this.buttonLoadProduct.Text = "Load";
            this.buttonLoadProduct.Font = new System.Drawing.Font("Consolas", 10F);
            this.buttonLoadProduct.ForeColor = System.Drawing.Color.White;
            this.buttonLoadProduct.BackColor = System.Drawing.Color.Transparent;
            this.buttonLoadProduct.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.buttonLoadProduct.FlatAppearance.BorderColor = System.Drawing.Color.White;
            this.buttonLoadProduct.Location = new System.Drawing.Point(20, 80);
            this.buttonLoadProduct.Size = new System.Drawing.Size(170, 24);
            this.buttonLoadProduct.Click += new System.EventHandler(this.buttonLoadProduct_Click);
            this.labelTimeRemaining = new System.Windows.Forms.Label();
            this.labelTimeRemaining.Text = "Time remaining: --";
            this.labelTimeRemaining.ForeColor = System.Drawing.Color.LightGreen;
            this.labelTimeRemaining.Font = new System.Drawing.Font("Consolas", 9F);
            this.labelTimeRemaining.Location = new System.Drawing.Point(20, 60);
            this.labelTimeRemaining.Size = new System.Drawing.Size(180, 17);
            // Add controls to panel
            this.panelProductLoad.Controls.Add(this.labelProductName);
            this.panelProductLoad.Controls.Add(this.buttonLoadProduct);
            this.panelProductLoad.Controls.Add(this.labelTimeRemaining);
            // Add to form
            this.Controls.Add(this.panelProductLoad);
        }

        #endregion

        private System.Windows.Forms.Panel panelContainer;
        private System.Windows.Forms.Button buttonExit;
        private System.Windows.Forms.Label labelUsername;
        private System.Windows.Forms.TextBox textBoxUsername;
        private System.Windows.Forms.Label labelPassword;
        private System.Windows.Forms.TextBox textBoxPassword;
        private System.Windows.Forms.CheckBox checkBoxRemember;
        private System.Windows.Forms.Button buttonSubmit;
        private System.Windows.Forms.Label labelStatus;
        private System.Windows.Forms.Panel topBarPanel;
        private System.Windows.Forms.Label topBarLabel;
        private System.Windows.Forms.Panel panelKeyActivation;
        private System.Windows.Forms.Label labelKeyPrompt;
        private System.Windows.Forms.TextBox textBoxKey;
        private System.Windows.Forms.Button buttonActivate;
        private System.Windows.Forms.Label labelKeyStatus;
        private System.Windows.Forms.Panel panelProductLoad;
        private System.Windows.Forms.Label labelProductName;
        private System.Windows.Forms.Button buttonLoadProduct;
        private System.Windows.Forms.Label labelTimeRemaining;
    }
} 