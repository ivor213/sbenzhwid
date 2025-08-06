const nodemailer = require('nodemailer');
const path = require('path');

class EmailService {
  constructor() {
    this.transporter = null;
    this.fromEmail = process.env.EMAIL_FROM || 'noreply@yourdomain.com';
    this.fromName = process.env.EMAIL_FROM_NAME || 'SBENZ Club';
    this.initialized = false;
    this.initializeTransporter();
  }

  async initializeTransporter() {
    // Use different configurations for development and production
    if (process.env.NODE_ENV === 'production') {
      // Production: Use SMTP (Gmail, SendGrid, etc.)
      this.transporter = nodemailer.createTransport({
        service: process.env.EMAIL_SERVICE || 'gmail',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASSWORD
        }
      });
    } else {
      // Development: Use Ethereal for testing
      try {
        // Create test account for Ethereal
        const testAccount = await nodemailer.createTestAccount();
        
        this.transporter = nodemailer.createTransport({
          host: 'smtp.ethereal.email',
          port: 587,
          secure: false,
          auth: {
            user: testAccount.user,
            pass: testAccount.pass
          }
        });
        
        console.log('✅ Ethereal email configured for development');
        console.log('📧 Test account:', testAccount.user);
        console.log('🔗 Preview URL: https://ethereal.email');
        this.initialized = true;
      } catch (error) {
        console.error('❌ Failed to create Ethereal test account:', error);
        // Fallback to a simple configuration
        this.transporter = nodemailer.createTransport({
          host: 'smtp.ethereal.email',
          port: 587,
          secure: false,
          auth: {
            user: 'test@ethereal.email',
            pass: 'test123'
          }
        });
        this.initialized = true;
      }
    }
  }

  async sendEmail(to, subject, html, text = null) {
    try {
      // Wait for transporter to be initialized
      if (!this.initialized) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
      
      const mailOptions = {
        from: `"${this.fromName}" <${this.fromEmail}>`,
        to: to,
        subject: subject,
        html: html,
        text: text || this.stripHtml(html)
      };

      const info = await this.transporter.sendMail(mailOptions);
      console.log('✅ Email sent successfully:', info.messageId);
      
      // In development, show Ethereal preview URL
      if (process.env.NODE_ENV !== 'production') {
        console.log('🔗 Preview URL: https://ethereal.email/message/' + info.messageId);
      }
      
      return { success: true, messageId: info.messageId };
    } catch (error) {
      console.error('❌ Email sending failed:', error);
      return { success: false, error: error.message };
    }
  }

  stripHtml(html) {
    return html.replace(/<[^>]*>/g, '');
  }

  // Order Confirmation Email
  async sendOrderConfirmation(order) {
    const subject = `Order Confirmation - ${order.orderId}`;
    const html = this.generateOrderConfirmationHTML(order);
    
    return await this.sendEmail(order.customerEmail, subject, html);
  }

  // Order Status Update Email
  async sendOrderStatusUpdate(order, newStatus) {
    const subject = `Order Status Updated - ${order.orderId}`;
    const html = this.generateOrderStatusUpdateHTML(order, newStatus);
    
    return await this.sendEmail(order.customerEmail, subject, html);
  }

  // Order Shipped Email
  async sendOrderShipped(order, trackingInfo = null) {
    const subject = `Your Order Has Been Shipped - ${order.orderId}`;
    const html = this.generateOrderShippedHTML(order, trackingInfo);
    
    return await this.sendEmail(order.customerEmail, subject, html);
  }

  // Order Delivered Email
  async sendOrderDelivered(order) {
    const subject = `Your Order Has Been Delivered - ${order.orderId}`;
    const html = this.generateOrderDeliveredHTML(order);
    
    return await this.sendEmail(order.customerEmail, subject, html);
  }

  // Welcome Email for New Users
  async sendWelcomeEmail(user) {
    const subject = 'Welcome to SBENZ Club!';
    const html = this.generateWelcomeEmailHTML(user);
    
    return await this.sendEmail(user.email, subject, html);
  }

  // Password Reset Email
  async sendPasswordReset(user, resetToken) {
    const subject = 'Password Reset Request - SBENZ Club';
    const html = this.generatePasswordResetHTML(user, resetToken);
    
    return await this.sendEmail(user.email, subject, html);
  }

  // Admin Notification for New Order
  async sendAdminOrderNotification(order) {
    const subject = `New Order Received - ${order.orderId}`;
    const html = this.generateAdminOrderNotificationHTML(order);
    
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@yourdomain.com';
    return await this.sendEmail(adminEmail, subject, html);
  }

  // Generate HTML Templates
  generateOrderConfirmationHTML(order) {
    const items = order.items.map(item => `
      <tr>
        <td style="padding: 12px; border-bottom: 1px solid #eee;">${item.name}</td>
        <td style="padding: 12px; border-bottom: 1px solid #eee; text-align: center;">${item.quantity}</td>
        <td style="padding: 12px; border-bottom: 1px solid #eee; text-align: right;">$${item.price.toFixed(2)}</td>
        <td style="padding: 12px; border-bottom: 1px solid #eee; text-align: right;">$${(item.price * item.quantity).toFixed(2)}</td>
      </tr>
    `).join('');

    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Order Confirmation</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #2c3e50; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f9f9f9; }
          .order-details { background: white; padding: 20px; margin: 20px 0; border-radius: 5px; }
          .table { width: 100%; border-collapse: collapse; }
          .table th, .table td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
          .table th { background: #f8f9fa; font-weight: bold; }
          .total { font-weight: bold; font-size: 18px; }
          .footer { text-align: center; padding: 20px; color: #666; font-size: 14px; }
          .button { display: inline-block; padding: 12px 24px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🎉 Order Confirmed!</h1>
            <p>Thank you for your purchase</p>
          </div>
          
          <div class="content">
            <h2>Order Details</h2>
            <div class="order-details">
              <p><strong>Order ID:</strong> ${order.orderId}</p>
              <p><strong>Order Date:</strong> ${new Date(order.createdAt).toLocaleDateString()}</p>
              <p><strong>Status:</strong> <span style="color: #27ae60;">Confirmed</span></p>
              
              <h3>Shipping Information</h3>
              <p>${order.shipping?.firstName} ${order.shipping?.lastName}</p>
              <p>${order.shipping?.address}</p>
              <p>${order.shipping?.city}, ${order.shipping?.state} ${order.shipping?.zipCode}</p>
              <p>${order.shipping?.country}</p>
              <p>Phone: ${order.shipping?.phone}</p>
            </div>
            
            <h3>Order Items</h3>
            <table class="table">
              <thead>
                <tr>
                  <th>Item</th>
                  <th style="text-align: center;">Qty</th>
                  <th style="text-align: right;">Price</th>
                  <th style="text-align: right;">Total</th>
                </tr>
              </thead>
              <tbody>
                ${items}
              </tbody>
            </table>
            
            <div style="text-align: right; margin-top: 20px;">
              <p><strong>Subtotal:</strong> $${order.totals?.subtotal?.toFixed(2) || '0.00'}</p>
              <p><strong>Shipping:</strong> $${order.totals?.shipping?.toFixed(2) || '0.00'}</p>
              <p><strong>Tax:</strong> $${order.totals?.tax?.toFixed(2) || '0.00'}</p>
              <p class="total">Total: $${order.totals?.total?.toFixed(2) || '0.00'}</p>
            </div>
            
            <div style="margin-top: 30px; text-align: center;">
              <a href="${process.env.WEBSITE_URL || 'http://localhost:3000'}/orders" class="button">Track Your Order</a>
            </div>
          </div>
          
          <div class="footer">
            <p>Thank you for choosing SBENZ Club!</p>
            <p>If you have any questions, please contact our support team.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  generateOrderStatusUpdateHTML(order, newStatus) {
    const statusMessages = {
      'processing': 'Your order is being processed and prepared for shipping.',
      'shipped': 'Your order has been shipped and is on its way to you.',
      'delivered': 'Your order has been successfully delivered.',
      'cancelled': 'Your order has been cancelled as requested.'
    };

    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Order Status Update</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #2c3e50; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f9f9f9; }
          .status-update { background: white; padding: 20px; margin: 20px 0; border-radius: 5px; }
          .button { display: inline-block; padding: 12px 24px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>📦 Order Status Update</h1>
          </div>
          
          <div class="content">
            <div class="status-update">
              <h2>Order ${order.orderId}</h2>
              <p><strong>New Status:</strong> <span style="color: #27ae60; text-transform: capitalize;">${newStatus}</span></p>
              <p>${statusMessages[newStatus] || 'Your order status has been updated.'}</p>
              
              <div style="margin-top: 20px;">
                <a href="${process.env.WEBSITE_URL || 'http://localhost:3000'}/orders" class="button">View Order Details</a>
              </div>
            </div>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  generateOrderShippedHTML(order, trackingInfo) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Order Shipped</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #27ae60; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f9f9f9; }
          .shipping-info { background: white; padding: 20px; margin: 20px 0; border-radius: 5px; }
          .button { display: inline-block; padding: 12px 24px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🚚 Your Order Has Been Shipped!</h1>
          </div>
          
          <div class="content">
            <div class="shipping-info">
              <h2>Order ${order.orderId}</h2>
              <p>Great news! Your order has been shipped and is on its way to you.</p>
              
              ${trackingInfo ? `
                <h3>Tracking Information</h3>
                <p><strong>Tracking Number:</strong> ${trackingInfo.number}</p>
                <p><strong>Carrier:</strong> ${trackingInfo.carrier}</p>
                <p><strong>Estimated Delivery:</strong> ${trackingInfo.estimatedDelivery}</p>
              ` : ''}
              
              <div style="margin-top: 20px;">
                <a href="${process.env.WEBSITE_URL || 'http://localhost:3000'}/orders" class="button">Track Your Order</a>
              </div>
            </div>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  generateOrderDeliveredHTML(order) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Order Delivered</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #27ae60; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f9f9f9; }
          .delivery-info { background: white; padding: 20px; margin: 20px 0; border-radius: 5px; }
          .button { display: inline-block; padding: 12px 24px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>✅ Your Order Has Been Delivered!</h1>
          </div>
          
          <div class="content">
            <div class="delivery-info">
              <h2>Order ${order.orderId}</h2>
              <p>Your order has been successfully delivered to your shipping address.</p>
              
              <h3>What's Next?</h3>
              <ul>
                <li>Inspect your items for any damage</li>
                <li>Test your hardware components</li>
                <li>Contact us if you need technical support</li>
                <li>Leave a review if you're satisfied</li>
              </ul>
              
              <div style="margin-top: 20px;">
                <a href="${process.env.WEBSITE_URL || 'http://localhost:3000'}/support" class="button">Get Support</a>
              </div>
            </div>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  generateWelcomeEmailHTML(user) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Welcome to SBENZ Club</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #2c3e50; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f9f9f9; }
          .welcome-info { background: white; padding: 20px; margin: 20px 0; border-radius: 5px; }
          .button { display: inline-block; padding: 12px 24px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🎉 Welcome to SBENZ Club!</h1>
          </div>
          
          <div class="content">
            <div class="welcome-info">
              <h2>Hello ${user.username}!</h2>
              <p>Welcome to SBENZ Club - your premier destination for high-quality hardware components and electronics.</p>
              
              <h3>What We Offer</h3>
              <ul>
                <li>Premium hardware components</li>
                <li>Fast and secure shipping</li>
                <li>Expert technical support</li>
                <li>Quality guarantee on all products</li>
              </ul>
              
              <div style="margin-top: 20px;">
                <a href="${process.env.WEBSITE_URL || 'http://localhost:3000'}" class="button">Start Shopping</a>
              </div>
            </div>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  generatePasswordResetHTML(user, resetToken) {
    const resetUrl = `${process.env.WEBSITE_URL || 'http://localhost:3000'}/reset-password?token=${resetToken}`;
    
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Password Reset</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #e74c3c; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f9f9f9; }
          .reset-info { background: white; padding: 20px; margin: 20px 0; border-radius: 5px; }
          .button { display: inline-block; padding: 12px 24px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🔐 Password Reset Request</h1>
          </div>
          
          <div class="content">
            <div class="reset-info">
              <h2>Hello ${user.username}!</h2>
              <p>We received a request to reset your password for your SBENZ Club account.</p>
              
              <p>Click the button below to reset your password:</p>
              
              <div style="margin: 30px 0; text-align: center;">
                <a href="${resetUrl}" class="button">Reset Password</a>
              </div>
              
              <p><strong>Important:</strong> This link will expire in 1 hour for security reasons.</p>
              
              <p>If you didn't request this password reset, please ignore this email.</p>
            </div>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  generateAdminOrderNotificationHTML(order) {
    const items = order.items.map(item => `
      <tr>
        <td>${item.name}</td>
        <td>${item.quantity}</td>
        <td>$${item.price.toFixed(2)}</td>
        <td>$${(item.price * item.quantity).toFixed(2)}</td>
      </tr>
    `).join('');

    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>New Order Notification</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #2c3e50; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f9f9f9; }
          .order-info { background: white; padding: 20px; margin: 20px 0; border-radius: 5px; }
          .table { width: 100%; border-collapse: collapse; }
          .table th, .table td { padding: 8px; text-align: left; border-bottom: 1px solid #eee; }
          .button { display: inline-block; padding: 12px 24px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🛒 New Order Received</h1>
          </div>
          
          <div class="content">
            <div class="order-info">
              <h2>Order ${order.orderId}</h2>
              <p><strong>Customer:</strong> ${order.customerEmail}</p>
              <p><strong>Total:</strong> $${order.totals?.total?.toFixed(2) || '0.00'}</p>
              <p><strong>Date:</strong> ${new Date(order.createdAt).toLocaleString()}</p>
              
              <h3>Order Items</h3>
              <table class="table">
                <thead>
                  <tr>
                    <th>Item</th>
                    <th>Qty</th>
                    <th>Price</th>
                    <th>Total</th>
                  </tr>
                </thead>
                <tbody>
                  ${items}
                </tbody>
              </table>
              
              <div style="margin-top: 20px;">
                <a href="${process.env.WEBSITE_URL || 'http://localhost:3000'}/admin" class="button">View in Admin Panel</a>
              </div>
            </div>
          </div>
        </div>
      </body>
      </html>
    `;
  }
}

module.exports = new EmailService(); 