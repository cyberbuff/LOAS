import { Button } from "@/components/ui/button";
import getConfig from 'next/config';

interface DownloadButtonProps {
  href?: string;
  label: string;
  filename?: string;
  type?: 'scpt' | 'swift' | 'binary' | 'app' | 'js';
}

export const DownloadButton: React.FC<DownloadButtonProps> = ({
  href,
  label,
  filename,
  type
}) => {
  const { publicRuntimeConfig } = getConfig();
  const version = publicRuntimeConfig?.version || '1.0.0';

  // If href is provided, use it directly
  if (href) {
    return (
      <Button asChild>
        <a href={href} download aria-label={label}>
          {label}
        </a>
      </Button>
    );
  }

  // Otherwise, construct the URL using the version and other props
  if (filename && type) {
    const baseUrl = `https://github.com/cyberbuff/loas/releases/download/${version}/${filename}`;
    const finalUrl = type === 'app' ? `${baseUrl}.zip` : baseUrl;

    return (
      <Button asChild>
        <a href={finalUrl} download aria-label={label}>
          {label}
        </a>
      </Button>
    );
  }

  // Fallback
  return (
    <Button disabled aria-label={label}>
      {label}
    </Button>
  );
};

export default DownloadButton;
