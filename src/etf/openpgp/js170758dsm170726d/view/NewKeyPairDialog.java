package etf.openpgp.js170758dsm170726d.view;

import java.awt.Choice;
import java.awt.Frame;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

public class NewKeyPairDialog extends PgpDialog  {
	/*
	 * Prozor za komunikaciju sa dalje 
	 */
	private JTextField[] textFields;
	private Choice[] choices;
	public NewKeyPairDialog(JFrame parent) {
		super(parent, "New key pair", 200, 200);
		setVisible(true);
	}
	@Override
	protected void setWindow() {
		GridLayout layout = new GridLayout(6, 2);
		layout.setHgap(5);
		layout.setVgap(5);
		setLayout(layout);
		setTextFields();
		setChoices();
		setButtons();
	}
	private void setTextFields() {
		textFields = new JTextField[3];
		JLabel[] labels = new JLabel[3];
		String[] labelName = {"Name", "Email", "Password"};
		
		for (int i = 0; i < textFields.length; i++) {
			if(i < 2) {
				textFields[i] = new JTextField();
			}else {
				textFields[i] = new JPasswordField();
			}
			labels[i] = new JLabel(labelName[i]);
			add(labels[i]);
			add(textFields[i]);
		}
	}
	private void setChoices() {
		choices = new Choice[2];
		JLabel[] labels = new JLabel[2];
		String[] labelName = {"DSA", "ElGammal"};
		for (int i = 0; i < labelName.length; i++) {
			labels[i] = new JLabel(labelName[i]);
			add(labels[i]);
			choices[i] = new Choice();
			add(choices[i]);
			choices[i].add("1024");
			choices[i].add("2048");
		}
		choices[1].add("4096");
	}
	private void setButtons() {
		JButton[] buttons = new JButton[2];
		String[] buttonName = {"Create", "Cancel"};
		for (int i = 0; i < buttons.length; i++) {
			buttons[i] = new JButton(buttonName[i]);
			add(buttons[i]);
			buttons[i].addActionListener(new ActionListener() {	
				@Override
				public void actionPerformed(ActionEvent e) {
					// TODO Auto-generated method stub
					if(e.getActionCommand().equals("Create")) {
						if(textFields[0].getText().isEmpty() || 
								textFields[1].getText().isEmpty() || 
								textFields[2].getText().isEmpty()) {
							JOptionPane.showMessageDialog(null, "You must imput all data first.");
						}else {
							((MainWindow)parent).createKeyPair(textFields[0].getText(), 
									textFields[1].getText(), 
									textFields[2].getText(), 
									Integer.parseInt(choices[0].getSelectedItem()), 
									Integer.parseInt(choices[1].getSelectedItem()));
					    	parent.setEnabled(true);
					    	dispose();
						}
					}else if(e.getActionCommand().equals("Cancel")) {
				    	parent.setEnabled(true);
				    	dispose();
					}
				}
			});
		}
	}
	@Override
	protected void setFileName(String fileName) {
		// TODO Auto-generated method stub
	}
}
