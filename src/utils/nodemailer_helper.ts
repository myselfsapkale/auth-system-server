import nodemailer from 'nodemailer';


/**
 * 
 * @name : transporter
 * @Desc : Creating a transporter which will help us in sending mails
 * 
 */


const transporter = nodemailer.createTransport({
    service: 'gmail', // you can use other services like 'hotmail', 'yahoo', etc.
    auth: {
        user: process.env.NODEMAILER_GMAIL_EMAIL, // your email address
        pass: process.env.NODEMAILER_GMAIL_LESS_SECURE_PASSWORD, // your email password
    },
    tls: {
        rejectUnauthorized: false // Note: This is often not recommended for production
    }
});


/**
 * 
 * @name : send_email_otp
 * @Desc : 
 * - For sending email with otp
 * - Mostly we will use for sending otp to user email
 * 
 */


const send_email_otp = async (to: string, subject: string, text: string, otp: string): Promise<void> => {
    text += `\n OTP - ${otp}`;
    await transporter.sendMail({
        from: process.env.NODEMAILER_GMAIL_EMAIL, // sender address
        to, // receiver address
        subject, // subject line
        text, // plain text body
    });
};


export { send_email_otp };