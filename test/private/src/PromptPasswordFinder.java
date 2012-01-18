/*
 * Copyright (c) Members of the EGEE Collaboration. 2004. See
 * http://www.eu-egee.org/partners/ for details on the copyright holders.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.UIManager;

import org.bouncycastle.openssl.PasswordFinder;

public class PromptPasswordFinder extends JPanel implements ActionListener, PasswordFinder{

    /**
	 * 
	 */
	private static final long serialVersionUID = -413461510613334587L;
	private static String OK = "ok";
    private static String HELP = "help";

    private JFrame controllingFrame; //needed for dialogs
    private JPasswordField passwordField;
    private JPanel newContentPane;
    private char[] password;
    private boolean done = false;

    public PromptPasswordFinder() {
        //Create and set up the window.
        controllingFrame = new JFrame("PasswordDemo");
        controllingFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        //Create and set up the content pane.
        newContentPane = new JPanel();


        //Create everything.
        passwordField = new JPasswordField(10);
        passwordField.setActionCommand(OK);
        passwordField.addActionListener(this);

        JLabel label = new JLabel("Enter the password: ");
        label.setLabelFor(passwordField);

        JComponent buttonPane = createButtonPanel();

        //Lay out everything.
        JPanel textPane = new JPanel(new FlowLayout(FlowLayout.TRAILING));
        textPane.add(label);
        textPane.add(passwordField);

        newContentPane.add(textPane);
        newContentPane.add(buttonPane);
    }

    protected JComponent createButtonPanel() {
        JPanel p = new JPanel(new GridLayout(0,1));
        JButton okButton = new JButton("OK");
        JButton helpButton = new JButton("Help");

        okButton.setActionCommand(OK);
        helpButton.setActionCommand(HELP);
        okButton.addActionListener(this);
        helpButton.addActionListener(this);

        p.add(okButton);
        p.add(helpButton);

        return p;
    }

    public void actionPerformed(ActionEvent e) {
        String cmd = e.getActionCommand();

        if (OK.equals(cmd)) { //Process the password.
            password = passwordField.getPassword();

            done = true;
            controllingFrame.removeAll();
            controllingFrame.removeNotify();
            controllingFrame.dispose();
            controllingFrame.setEnabled(false);
        } else { //The user has asked for help.
            JOptionPane.showMessageDialog(controllingFrame,
                "You can get the password by searching this example's\n"
              + "source code for the string \"correctPassword\".\n"
              + "Or look at the section How to Use Password Fields in\n"
              + "the components section of The Java Tutorial.");
        }
    }

   //Must be called from the event dispatch thread.
    protected void resetFocus() {
        passwordField.requestFocusInWindow();
    }

    /**
     * Create the GUI and show it.  For thread safety,
     * this method should be invoked from the
     * event dispatch thread.
     */
    private void createAndShowGUI() {
        //Create and set up the content pane.
        newContentPane.setOpaque(true); //content panes must be opaque
        controllingFrame.setContentPane(newContentPane);

        //Make sure the focus goes to the right component
        //whenever the frame is initially given the focus.
        controllingFrame.addWindowListener(new WindowAdapter() {
            public void windowActivated(WindowEvent e) {
               resetFocus();
            }
        });

        //Display the window.
        controllingFrame.pack();
        controllingFrame.setVisible(true);
    }

    public char[] getPassword() {
		UIManager.put("swing.boldMetal", Boolean.FALSE);
		createAndShowGUI();
		System.out.println("showed");
		System.out.println(done);
		boolean showed = false;
		while (controllingFrame.isVisible()) {
			if(showed == false)
				System.out.println("visi");
//				showed = true;
			showed = true;
		}
		return password;

	}

}
