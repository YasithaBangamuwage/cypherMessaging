
import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.util.Properties;

public class MailUtil
{
  public static void sendMail(String subject, String recipient, String privateKey)
  {
    final String username = "apogeeakila@gmail.com";
    final String password = "ZAQ@12345";

    Properties props = new Properties();
    props.put("mail.smtp.auth", true);
    props.put("mail.smtp.starttls.enable", true);
    props.put("mail.smtp.host", "smtp.gmail.com");
    props.put("mail.smtp.port", "587");

    Session session = Session.getInstance(props, new javax.mail.Authenticator()
      {
        protected javax.mail.PasswordAuthentication getPasswordAuthentication()
        {
          return new PasswordAuthentication(username, password);
        }
      });

    try
    {

      Message message = new MimeMessage(session);
      message.setFrom(new InternetAddress("apogeeakila@gmail.com"));
      message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(recipient));
      message.setSubject(subject);
      message.setText(privateKey);

      System.out.println("email Sending");

      Transport.send(message);

      System.out.println("email sent Done");

    }
    catch (MessagingException e)
    {
      e.printStackTrace();
    }
  }
}
