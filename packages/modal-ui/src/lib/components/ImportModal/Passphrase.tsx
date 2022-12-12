import React, { Fragment } from "react";
import generator from "generate-password";
import { translate } from "@near-wallet-selector/core";
import { ModalHeader } from "../ModalHeader";
import ClickToCopy from "../ClickToCopy";

export interface PassphraseProps {
  onNextStep: () => void;
  hasCopied: boolean;
  setHasCopied: (hasCopied: boolean) => void;
  onCloseModal: () => void;
  onBack: () => void;
}

export const Passphrase: React.FC<PassphraseProps> = ({
  onNextStep,
  hasCopied,
  setHasCopied,
  onCloseModal,
  onBack,
}) => {
  // TODO: reserve this secret key and pass down to next step for encryption for WEP-213
  const secretKey = generator.generate({
    length: 10,
    numbers: true,
    strict: true,
    lowercase: true,
    uppercase: true,
    symbols: true,
  });

  const onCheck = (check: boolean) => setHasCopied(check);

  return (
    <Fragment>
      <ModalHeader
        title={translate("modal.importAccounts.getPassphrase.title")}
        onCloseModal={onCloseModal}
        onBack={onBack}
      />
      <div className="import-account">
        <div className="content">
          <h4 className="passhrase-title">
            {translate("modal.importAccounts.getPassphrase.desc")}
          </h4>
          <ClickToCopy copy={secretKey} id="passphraseButton">
            <div className="passphrase-text">{secretKey}</div>
          </ClickToCopy>
          <label htmlFor="passphraseButton" className="passphrase-label">
            {translate("modal.importAccounts.getPassphrase.label")}
          </label>
          <div className="filler" />
          <div className="checkbox">
            <input
              onChange={(e) => {
                onCheck(e.target.checked);
              }}
              checked={hasCopied}
              type="checkbox"
              id="passphrase-check"
              name="passphrase-check"
              value="passphrase-check"
            />
            <label htmlFor="passphrase-check">
              {translate("modal.importAccounts.getPassphrase.checkLabel")}
            </label>
          </div>
          <button
            className="middleButton import-account-button"
            onClick={onNextStep}
            disabled={!hasCopied}
          >
            {translate("modal.importAccounts.getPassphrase.button")}
          </button>
        </div>
      </div>
    </Fragment>
  );
};
