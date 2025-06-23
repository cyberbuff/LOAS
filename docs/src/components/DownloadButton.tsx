import { Button } from "@/components/ui/button";
import { useVersion } from "@/hooks/use-version";

interface DownloadButtonProps {
  href?: string;
  label: string;
  filename?: string;
  directory?: string;
  type?: 'scpt' | 'swift' | 'binary' | 'app' | 'js';
}

export const DownloadButton: React.FC<DownloadButtonProps> = ({
  href,
  label,
  filename,
  directory,
  type
}) => {
  const version = useVersion();

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
  if (filename && directory && type) {
    const baseUrl = `https://github.com/cyberbuff/loas/releases/download/${version}/${directory}/${filename}`;
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
