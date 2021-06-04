package etf.openpgp.js170758dsm170726d.view;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.math.BigInteger;
import java.util.List;

import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import org.bouncycastle.openpgp.PGPPrivateKey;

import etf.openpgp.js170758dsm170726d.controller.KeyData;
import etf.openpgp.js170758dsm170726d.controller.PgpProtocol;

public class MainWindow extends JFrame implements ActionListener {
	private final static String NEW_KEY_PAIR = "New key pair";
	private final static String IMPORT_KEY = "Import key";
	private final static String ENCRYPT_FILE = "Sign/Encrypt file";
	private final static String DECRYPT_FILE = "Decrypt/Verify file";
	private final static String EXIT = "Exit";
	private final static String EXPORT_PUBLIC = "Export public";
	private final static String EXPORT_SECRET = "Export secret";
	private final static String DELETE = "Delete";

	private JTable table;
	private DefaultTableModel model; 
	private PgpProtocol pgpProtocol; //Referenca na klasu PGP za dalji rad sa njom

	public MainWindow() {
		super("OpenPGP");
		pgpProtocol = new PgpProtocol();
		setSize(1000, 400);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setWindow();
		setVisible(true);
	}
	private void setWindow() {//Prikazivanje dva dela osnovnog prozora
		setMenu();
		setTable();
	}
	public PgpProtocol getPgpProtocol() {
		return pgpProtocol;
	}
	
	public void createKeyPair(String name, 	String email, 	String password, int dsaBitLength, int elGamalBitLength) {
		KeyData key = pgpProtocol.generateKeyPair(name, email, password, dsaBitLength, elGamalBitLength);
		Object[] data = { key.getName(), key.getEmail(), key.getKeyID().toUpperCase() };
		model.addRow(data);
	}
	/*
	 * Naredna metoda je metoda za dalje 
	 */
	@Override
	public void actionPerformed(ActionEvent e) {
		String command = e.getActionCommand();
		if (command.equals(EXIT)) {
			this.dispose();
			this.setVisible(false);
		} else if (command.equals(NEW_KEY_PAIR)) {
			setEnabled(false);
			new NewKeyPairDialog(this);
		} else {
			setEnabled(false);
			JFileChooser fileChooser = new JFileChooser();
			int returnVal = fileChooser.showOpenDialog(this);

			if (returnVal == JFileChooser.APPROVE_OPTION) {
				File file = fileChooser.getSelectedFile();
				if(command.equals(IMPORT_KEY)) {
					KeyData key = pgpProtocol.importKey(file.getAbsolutePath());
					Object[] data = { key.getName(), key.getEmail(), key.getKeyID().toUpperCase() };
					model.addRow(data);
					setEnabled(true);
				}
				else if(command.equals(ENCRYPT_FILE)) {
					new SendMessageDialog(this, file.getAbsolutePath());
				}
				else if(command.equals(DECRYPT_FILE)) {
					pgpProtocol.receiveMessage(file.getAbsolutePath());
					
					setEnabled(true);
				}
				else if(command.equals(EXPORT_PUBLIC)) {
					BigInteger keyID = new BigInteger(String.valueOf(model.getValueAt(table.getSelectedRow(), 2)), 16);
					pgpProtocol.exportPublicKey(file.getAbsolutePath(), keyID.longValue());
					setEnabled(true);
				}
				else if(command.equals(EXPORT_SECRET)) {
					BigInteger keyID = new BigInteger(String.valueOf(model.getValueAt(table.getSelectedRow(), 2)), 16);
					pgpProtocol.exportSecretKey(file.getAbsolutePath(), keyID.longValue());	
					setEnabled(true);
				}
			} else {
				setEnabled(true);
			}
		}
	}

	

	private void setMenu() { //Metoda koja fromira Menubar
		JMenuBar menuBar = new JMenuBar();
		JMenu menu = new JMenu("File");

		JMenuItem jmi1 = new JMenuItem(NEW_KEY_PAIR);
		JMenuItem jmi2 = new JMenuItem(IMPORT_KEY);
		JMenuItem jmi3 = new JMenuItem(ENCRYPT_FILE);
		JMenuItem jmi4 = new JMenuItem(DECRYPT_FILE);
		JMenuItem jmi5 = new JMenuItem(EXIT);

		jmi1.addActionListener(this);
		jmi2.addActionListener(this);
		jmi3.addActionListener(this);
		jmi4.addActionListener(this);
		jmi5.addActionListener(this);

		menu.add(jmi1);
		menu.add(jmi2);
		menu.add(jmi3);
		menu.add(jmi4);
		menu.addSeparator();
		menu.add(jmi5);
		menu.addActionListener(this);

		menuBar.add(menu);
		setJMenuBar(menuBar);

	}
	/*
	 * U nastavku su metoda za rad sa tabelom 
	 */
	private void setTable() { //Metoda koja fromira tabelu prikaza
		String[] columnNames = { "Name", "E-Mail", "Key-ID" };
		model = new DefaultTableModel(0, columnNames.length);
		model.setColumnIdentifiers(columnNames);

		table = new JTable(model);
		JScrollPane scrollPane = new JScrollPane(table);
		table.setFillsViewportHeight(true);
		table.setDefaultEditor(Object.class, null);
		table.setDefaultRenderer(table.getColumnClass(0), new RowRenderer(pgpProtocol));
		
		fillTable();
		
		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				// TODO Auto-generated method stub
				if(e.getButton() == MouseEvent.BUTTON3 && table.getSelectedRow() >= 0) {
					showPopUpMenu(e);
				}

			}
		});

		add(scrollPane, BorderLayout.CENTER);
	}
	
	private void fillTable() {	//Metoda koja popunjava tabelu
		List<KeyData> keyList = pgpProtocol.getSecretKeys();
		
		for (KeyData data : pgpProtocol.getPublicKeys()) {
			if(!keyList.contains(data)) {
				keyList.add(data);
			}
		}
		
		for (KeyData key : keyList) {
			Object[] data = { key.getName(), key.getEmail(), key.getKeyID().toUpperCase() };
			model.addRow(data);
		}
	}
	/*
	 * Metoda za pop up meni , koja se pojavljuje na desni klik misem za 
	 */
	private void showPopUpMenu(MouseEvent me) {
		JPopupMenu popupMenu = new JPopupMenu();
		
		JMenuItem exportPublicKeyMenuItem = new JMenuItem(EXPORT_PUBLIC);
		popupMenu.add(exportPublicKeyMenuItem);

		JMenuItem exportSecretKeyMenuItem = new JMenuItem(EXPORT_SECRET);
		popupMenu.add(exportSecretKeyMenuItem);
		BigInteger keyID = new BigInteger(String.valueOf(model.getValueAt(table.getSelectedRow(), 2)), 16);
		exportSecretKeyMenuItem.setEnabled(pgpProtocol.isSecretKey(keyID.longValue()));
		
		popupMenu.addSeparator();
		JMenuItem deleteMenuItem = new JMenuItem(DELETE);
		popupMenu.add(deleteMenuItem);
		
		popupMenu.show(me.getComponent(), me.getX(), me.getY());
		deleteMenuItem.addActionListener(new ActionListener() {
			
			@Override
		public void actionPerformed(ActionEvent e) {
				// TODO Auto-generated method stub
				int dialogResult = JOptionPane.showConfirmDialog(null, "Are you sure?","Delete", 
													JOptionPane.YES_NO_OPTION);
				if(dialogResult == JOptionPane.YES_OPTION) {
					Long keyID = KeyData.getLongFromHexString(String.valueOf(model.getValueAt(table.getSelectedRow(), 2)));
					if(pgpProtocol.isSecretKey(keyID)) {
						JPasswordField passField = new JPasswordField();
						int ok = JOptionPane.showConfirmDialog(null, passField, "Enter Password", 
																JOptionPane.OK_CANCEL_OPTION, 
																JOptionPane.PLAIN_MESSAGE);
						while(ok == JOptionPane.OK_OPTION) {
							if(pgpProtocol.isSecretKey(keyID)) {
								PGPPrivateKey privateKey = pgpProtocol.getPrivateKey(keyID, passField.getPassword());
								if(privateKey != null) {
									pgpProtocol.deleteKeyPair(keyID);
									model.removeRow(table.getSelectedRow());
									break;
								}
								else {
									JOptionPane.showConfirmDialog(null, "Wrong password!", "Error", JOptionPane.DEFAULT_OPTION);
									passField.setText(null);
									ok = JOptionPane.showConfirmDialog(null, passField, "Enter Password", 
											JOptionPane.OK_CANCEL_OPTION, 
											JOptionPane.PLAIN_MESSAGE);
								}
							}
							
						}

					}
					else {
						pgpProtocol.deleteKeyPair(keyID);
						model.removeRow(table.getSelectedRow());	
					}

					
				}
			}
		});
		exportPublicKeyMenuItem.addActionListener(this);
		exportSecretKeyMenuItem.addActionListener(this);

	}

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		new MainWindow();
	}

}
