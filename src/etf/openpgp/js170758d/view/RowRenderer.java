package etf.openpgp.js170758d.view;

import java.awt.Color;
import java.awt.Component;
import java.math.BigInteger;

import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

import etf.openpgp.js170758d.controller.PgpProtocol;

public class RowRenderer extends DefaultTableCellRenderer {
	private PgpProtocol pgpProtocol;
	
	public RowRenderer(PgpProtocol protocol) {
		super();
		pgpProtocol = protocol;
	}
	
	public Component getTableCellRendererComponent(JTable table, Object value, 
													boolean isSelected, boolean hasFocus, 
													int row, int column) {
		super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
		
		BigInteger keyID = new BigInteger(String.valueOf(table.getModel().getValueAt(row, 2)), 16);
		if(isSelected) {
			setBackground(Color.LIGHT_GRAY);
		}
		else if(pgpProtocol.isSecretKey(keyID.longValue())) {
			
			setBackground(Color.GREEN);			
		}
		else {
			setBackground(Color.WHITE);
		}
		
		return this;
	}

}
