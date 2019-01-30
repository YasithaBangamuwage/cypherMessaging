import java.awt.EventQueue;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.swing.*;
import javax.swing.border.EmptyBorder;

/**
 * @author YAS
 * @version 1.2
 * @category Used to get user inputs to manage users in the app.
 */
public class CypherManager extends JFrame
{

  private static final long serialVersionUID = 1L;
  private JPanel contentPane;
  private JTextField asyCMessage;
  private JTextField txtEmail;
  private JTextArea txtPrivateKey;
  private JTextArea txtMsgEnrypted;

  private static RSAKeyPairGenerator rsaKeyPairGenerator;
  private static String cypherTextString = null;

  private final String emailRegex =
    "^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@" + "[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$";

  /**
   * Launch the application.
   */
  public static void main(String[] args) throws NoSuchAlgorithmException
  {

    rsaKeyPairGenerator = new RSAKeyPairGenerator();

    EventQueue.invokeLater(new Runnable()
      {
        public void run()
        {
          try
          {
            CypherManager frame = new CypherManager();
            frame.setVisible(true);
          }
          catch (Exception e)
          {
            e.printStackTrace();
          }
        }
      });
  }

  /**
   * Create the frame.
   */
  @SuppressWarnings("serial")
  public CypherManager()
  {
    setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    setBounds(100, 100, 604, 500);
    contentPane = new JPanel();
    contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
    setContentPane(contentPane);
    contentPane.setLayout(null);

    final JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
    tabbedPane.setBounds(10, 46, 568, 400);
    contentPane.add(tabbedPane);

    JPanel asymmetricCypherPanel = new JPanel();
    tabbedPane.addTab("Asymmetric", null, asymmetricCypherPanel, null);
    asymmetricCypherPanel.setLayout(null);

    JLabel lblACMessage = new JLabel("Message");
    lblACMessage.setFont(new Font("Tahoma", Font.PLAIN, 12));
    lblACMessage.setBounds(58, 29, 100, 16);
    asymmetricCypherPanel.add(lblACMessage);

    asyCMessage = new JTextField();
    asyCMessage.setBounds(126, 28, 294, 20);
    asymmetricCypherPanel.add(asyCMessage);
    asyCMessage.setColumns(10);

    JLabel label_2 = new JLabel("Email");
    label_2.setFont(new Font("Tahoma", Font.PLAIN, 12));
    label_2.setBounds(58, 61, 58, 16);
    asymmetricCypherPanel.add(label_2);

    txtEmail = new JTextField();
    txtEmail.setColumns(10);
    txtEmail.setBounds(126, 60, 294, 20);
    asymmetricCypherPanel.add(txtEmail);

    final JLabel asyCInfo = new JLabel("");
    asyCInfo.setBounds(210, 350, 257, 14);
    asymmetricCypherPanel.add(asyCInfo);

    // validate form inputs and encrypt, send mail
    JButton btnAsyCEncrypt = new JButton("Encrypt and send Mail");
    btnAsyCEncrypt.addActionListener(new ActionListener()
      {
        public void actionPerformed(ActionEvent arg0)
        {
          if (!asyCMessage.getText().equals(""))
          {
            // check user email is valid or not
            if (txtEmail.getText().matches(emailRegex))
            {
              //can do encrypt, send mail
              try
              {
                cypherTextString = rsaKeyPairGenerator.encrypt(asyCMessage.getText());

                txtMsgEnrypted.setText(cypherTextString);
                String privateKey =
                  Base64.getEncoder().encodeToString(rsaKeyPairGenerator.getPair().getPrivate().getEncoded());

                MailUtil.sendMail("Asymmetric Cypher", txtEmail.getText(), privateKey);
                asyCInfo.setText("Email send successfully");

              }
              catch (Exception e)
              {
                asyCInfo.setText("Something went wrong when doing encryption");
              }

            }
            else
            {
              // not match email
              asyCInfo.setText("Email is not valid one.");
            }
          }
          else
          {
            // not match id
            asyCInfo.setText("Message can not be empty");
          }
        }
      });
    btnAsyCEncrypt.setBounds(220, 90, 200, 23);
    asymmetricCypherPanel.add(btnAsyCEncrypt);

    JLabel lblDecyptInfo = new JLabel("Encrypted");
    lblDecyptInfo.setFont(new Font("Tahoma", Font.PLAIN, 12));
    lblDecyptInfo.setBounds(58, 130, 255, 16);
    asymmetricCypherPanel.add(lblDecyptInfo);

    txtMsgEnrypted = new JTextArea(5, 20);
    txtMsgEnrypted.setBounds(126, 130, 294, 40);
    asymmetricCypherPanel.add(txtMsgEnrypted);

    JLabel lblPrivateKey = new JLabel("Private Key");
    lblPrivateKey.setFont(new Font("Tahoma", Font.PLAIN, 12));
    lblPrivateKey.setBounds(58, 200, 100, 16);
    asymmetricCypherPanel.add(lblPrivateKey);

    txtPrivateKey = new JTextArea(5, 20);
    txtPrivateKey.setBounds(126, 200, 294, 40);
    asymmetricCypherPanel.add(txtPrivateKey);

    JLabel lblDecryptMsg = new JLabel("Decrypted - ");
    lblDecryptMsg.setFont(new Font("Tahoma", Font.PLAIN, 12));
    lblDecryptMsg.setBounds(58, 290, 255, 16);
    asymmetricCypherPanel.add(lblDecryptMsg);

    JButton btnAsyCDecrypt = new JButton("Decrypt Message");
    btnAsyCDecrypt.addActionListener(new ActionListener()
      {
        public void actionPerformed(ActionEvent arg0)
        {
          if (txtPrivateKey.getText().equals(""))
          {
            asyCInfo.setText("Private key can not be empty");
          }
          else
          {
            String decryptedMessage = "";
            try
            {
              decryptedMessage =
                rsaKeyPairGenerator.decryptWithGivenPrivateKey(cypherTextString, txtPrivateKey.getText());
            }
            catch (Exception e)
            {
              e.printStackTrace();
            }
            lblDecryptMsg.setText("Decrypted - " + decryptedMessage);
            asyCInfo.setText("Decrypted successfully");
          }
        }
      });
    btnAsyCDecrypt.setBounds(220, 260, 200, 23);
    asymmetricCypherPanel.add(btnAsyCDecrypt);

    // clear new user tab form
    JButton btnClear = new JButton("Clear");
    btnClear.addActionListener(new ActionListener()
      {
        public void actionPerformed(ActionEvent arg0)
        {
          asyCMessage.setText("");
          txtEmail.setText("");
          asyCInfo.setText("");
          lblDecryptMsg.setText("Decrypted - ");
          txtMsgEnrypted.setText("");
          txtPrivateKey.setText("");
        }
      });
    btnClear.setBounds(330, 310, 89, 23);
    asymmetricCypherPanel.add(btnClear);

    JLabel lblUserManager = new JLabel("Cypher Manager ");
    lblUserManager.setFont(new Font("Tahoma", Font.BOLD, 16));
    lblUserManager.setBounds(10, 11, 300, 24);
    contentPane.add(lblUserManager);

  }

}
