package etf.openpgp.js170758d.view;

import java.awt.GridLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import javax.swing.JDialog;
import javax.swing.JFrame;

public abstract class PgpDialog extends JDialog {

	protected JFrame parent;

	public PgpDialog(JFrame parent, String dialogName, int width, int height) {
		super(parent, dialogName, true);
		this.parent = parent;
		setSize(width, height);
		setResizable(false);
		
		//setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);
		addWindowListener(new WindowAdapter() {
		    @Override
		    public void windowClosing(WindowEvent e) {
		    	parent.setEnabled(true);
		    	dispose();
		    }
		});
		setWindow();

		
	}
	
	protected abstract void setWindow();
	protected abstract void setFileName(String fileName);
	
}
