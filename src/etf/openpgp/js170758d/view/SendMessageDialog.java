package etf.openpgp.js170758d.view;

import java.awt.Choice;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.LinkedList;
import java.util.List;

import javax.security.auth.login.FailedLoginException;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;

import org.bouncycastle.openpgp.PGPPrivateKey;

import etf.openpgp.js170758d.controller.KeyData;
import etf.openpgp.js170758d.controller.PgpProtocol;

public class SendMessageDialog extends PgpDialog {
	private JTextField fileNameTextField;
	private JCheckBox[] checkBoxes;
	private Choice[] choices;
	private JList<String> receiversList;
	private DefaultListModel<String> receiversListModel;
	private String fileName;
	
	public SendMessageDialog(JFrame parent, String fileName) {
		super(parent, "Send message", 400, 400);
		setFileName(fileName);
		setVisible(true);
	}

	@Override
	protected void setWindow() {
		setLayout(new GridBagLayout());
		
		setLabels();
		setTextField();
		setCheckBoxes();
		setChoices();
		setReceiversList();
		setButtons();
	}
	
	protected void setFileName(String fileName) {
		this.fileName = fileName;
		fileNameTextField.setEnabled(true);
		fileNameTextField.setText(fileName);
		fileNameTextField.setEnabled(false);
	}
	
	private void setLabels() {
		String[] labels = {"File name", "Signature", "Encrypt", "Receivers", "Algorithm", "Compress", "Convert"};
		for (int i = 0; i < labels.length; i++) {
			addComponent(new JLabel(labels[i]), 0, i, 0.2, 0.1);
		}
	}
	
	private void setTextField() {
		fileNameTextField = new JTextField();
		fileNameTextField.setEnabled(false);
		addComponent(fileNameTextField, 2, 0, 0.75, 0.1);
	}
	
	private void setCheckBoxes() {
		checkBoxes = new JCheckBox[4];
		
		int space = 1;
		for (int i = 0; i < checkBoxes.length; i++) {
			checkBoxes[i] = new JCheckBox();
			checkBoxes[i].addItemListener(new ItemListener() {
				
				@Override
				public void itemStateChanged(ItemEvent e) {
					// TODO Auto-generated method stub
					if(e.getSource().equals(checkBoxes[0])) {
						choices[0].setEnabled(e.getStateChange() == 1);
					}
					else if(e.getSource().equals(checkBoxes[1])) {
						choices[1].setEnabled(e.getStateChange() == 1);
					}
				}
			});
			addComponent(checkBoxes[i], 1, i + space, 0.05, 0.1);	
			if(i == 1) {
				space = 3;
			}
		}
	}
	
	private void setChoices() {
		choices = new Choice[3];
		int space = 1;
		for (int i = 0; i < choices.length; i++) {
			choices[i] = new Choice();
			if(i < 2) {
				choices[i].setEnabled(false);
				List<KeyData> items = null;
				if(i == 0) {
					items = ((MainWindow)parent).getPgpProtocol().getSecretKeys();
				}
				else {
					items = ((MainWindow)parent).getPgpProtocol().getPublicKeys();
				}
				
				for (KeyData item : items) {
					choices[i].add(item.toString());
				}
			}
			else {
				choices[i].add("CAST-5");
				choices[i].add("TripleDES");
			}

			addComponent(choices[i], 2, i + space, 0.75, 0.1);
			if(i == 1) {
				space = 2;
			}
		}

		choices[1].addItemListener(new ItemListener() {
			
			@Override
			public void itemStateChanged(ItemEvent e) {
				// TODO Auto-generated method stub
				if(!receiversListModel.contains(e.getItem())) {
					receiversListModel.addElement(e.getItem().toString());					
				}

			}
		});
	}
	
	private void setReceiversList() {

		receiversListModel = new DefaultListModel<String>();
		receiversList = new JList<String>(receiversListModel); 
		receiversList.setSize(getMaximumSize());
		
		JScrollPane scrollPane = new JScrollPane(receiversList);
		receiversList.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				// TODO Auto-generated method stub
				if(e.getButton() == MouseEvent.BUTTON3) {
					if(receiversList.getSelectedValue() != null) {
						showPopUpMenu(e);						
					}

				}

			}
		});
		
		addComponent(scrollPane, 2, 3, 0.75, 0.5);
	}
	
	
	private void setButtons() {
		JButton[] buttons = new JButton[2];
		String[] buttonName = {"Encrypt", "Cancel"};
		
		for (int i = 0; i < buttons.length; i++) {
			buttons[i] = new JButton(buttonName[i]);
			if(i == 1) {
				addComponent(buttons[i], 2, 7, 0.3, 0.1);
			}
			else {
				addComponent(buttons[i], 0, 7, 0.3, 0.1);
			}

			buttons[i].addActionListener(new ActionListener() {
				
				@Override
				public void actionPerformed(ActionEvent e) {
					// TODO Auto-generated method stub
					if(e.getActionCommand().equals("Encrypt")) {
						sendMessage();
					}
					else if(e.getActionCommand().equals("Cancel")) {
				    	parent.setEnabled(true);
				    	dispose();
					}
				}
			});
		}
		
	}
	
	private void sendMessage() {
		String signature = checkBoxes[0].isSelected() ? choices[0].getSelectedItem() : null;
		Long signKey = null;
		char[] pass = null;
		if(signature != null) {
			signKey = KeyData.getLongFromHexString(KeyData.parseData(signature)[0]);
			pass = showPasswordDialog(signKey);
		}
		
		if(signature == null || pass != null) {
			List<Long> encryptFor = null;
			if(checkBoxes[1].isSelected()) {
				encryptFor = new LinkedList<Long>();
				for (int i = 0; i < receiversListModel.getSize(); i++) {
					String receiver = receiversListModel.getElementAt(i);
					encryptFor.add(KeyData.getLongFromHexString(KeyData.parseData(receiver)[0]));
				}
			}

			String algorithm = choices[2].getSelectedItem();
			boolean compress = checkBoxes[2].isSelected();
			boolean convertToRadix64 = checkBoxes[3].isSelected();
			
	    	((MainWindow)parent).getPgpProtocol().sendMessage(fileName, signKey, pass, encryptFor, algorithm, compress, convertToRadix64);
			parent.setEnabled(true);
	    	dispose();
		}

	}
	
	private void addComponent(Component comp, int x, int y, double weightx, double weighty) {
		
		GridBagConstraints constraints = new GridBagConstraints();
		constraints.fill = GridBagConstraints.BOTH;
		constraints.anchor = GridBagConstraints.CENTER;
		constraints.weightx = weightx;
		constraints.weighty = weighty;
		constraints.gridx = x;
		constraints.gridy = y;
		constraints.insets = new Insets(5,5,5,5);
		add(comp, constraints);
	}
	
	private void showPopUpMenu(MouseEvent me) {
		JPopupMenu popupMenu = new JPopupMenu();
		JMenuItem menuItem = new JMenuItem("Remove");
		popupMenu.add(menuItem);
		popupMenu.show(me.getComponent(), me.getX(), me.getY());
		menuItem.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				// TODO Auto-generated method stub
				if(e.getActionCommand() == "Remove") {
					receiversListModel.remove(receiversList.getSelectedIndex());
				}
			}
		});

	}

	private char[] showPasswordDialog(Long keyID) {
		JPasswordField passField = new JPasswordField();
		int ok = JOptionPane.showConfirmDialog(null, passField, "Enter Password", 
												JOptionPane.OK_CANCEL_OPTION, 
												JOptionPane.PLAIN_MESSAGE);
		while(ok == JOptionPane.OK_OPTION) {
			PGPPrivateKey privateKey = ((MainWindow)parent).getPgpProtocol()
														.getPrivateKey(keyID, passField.getPassword());
			if(privateKey != null) {
				return passField.getPassword();
			}
			else {
				JOptionPane.showConfirmDialog(null, "Wrong password!", "Error", JOptionPane.DEFAULT_OPTION);
				passField.setText(null);
				ok = JOptionPane.showConfirmDialog(null, passField, "Enter Password", 
						JOptionPane.OK_CANCEL_OPTION, 
						JOptionPane.PLAIN_MESSAGE);
			}
		}
		return null;	
	}
	
}
